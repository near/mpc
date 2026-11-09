//! Where a node's platform stands against Intel's TCB requirements.
//!
//! Every verdict comes from [`dcap_qvl`], the same verification the contract
//! runs; this module only chooses which collateral it runs against.

use std::time::Duration;

use anyhow::{Context as _, bail};
use attestation::attestation::DstackAttestation;
use clap::ValueEnum;
use dcap_qvl::{
    QuoteCollateralV3, SvnShortfall, TcbStatus,
    collateral::{CollateralClient, INTEL_PCS_URL, TcbEvaluationDataSet},
    policy::{PckIdentity, QuoteClaims, QuotePolicy},
    quote::{Quote, TDReport10},
    tcb_info::TcbInfo,
    verify::QuoteVerifier,
};
use mpc_attestation::{attestation::Attestation, dcap_conversions::collateral_into_dcap};
use node_types::http_server::StaticWebData;

/// Timeout around a whole collateral fetch, which makes several requests.
const PCS_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum EvaluationDataSet {
    Standard,
    Early,
}

#[expect(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum TcbVerdict {
    /// DCAP's verdict and the TCB info it was reached against. The platform's
    /// own SVNs are in [`QuoteClaims`], under `platform.pck` and `report`.
    Verified {
        tcb_info: TcbInfo,
        claims: QuoteClaims,
        /// Empty in three cases: the platform clears an accepted level, Intel
        /// accepts no level at all, or every SVN clears one and the module
        /// identity's advisories carry the status down. Only the first is
        /// `UpToDate`; the other two print a line saying nothing can be raised.
        shortfalls: Vec<SvnShortfall>,
    },
    /// No status at all. Usually expired collateral in a long-running node's
    /// boot-time snapshot.
    Rejected(String),
}

impl TcbVerdict {
    pub fn is_up_to_date(&self) -> bool {
        matches!(self, Self::Verified { claims, .. } if claims.tcb.status == TcbStatus::UpToDate)
    }

    fn status_and_set(&self) -> Option<(TcbStatus, u32)> {
        match self {
            Self::Verified {
                tcb_info, claims, ..
            } => Some((claims.tcb.status, tcb_info.tcb_evaluation_data_number)),
            Self::Rejected(_) => None,
        }
    }
}

pub struct Report {
    /// Parsed from the quote itself, so the platform's own numbers survive even
    /// when no collateral verifies.
    pub td_report: TDReport10,
    /// What the node's own boot-time collateral says, which can lag by days.
    pub served: TcbVerdict,
    /// What the contract decides today, against collateral fetched just now.
    pub standard: Option<TcbVerdict>,
    /// What it will decide once Intel promotes the set it publishes early.
    pub early: Option<TcbVerdict>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EarlyDemotion {
    pub cleared: u32,
    pub demoted: u32,
}

impl Report {
    /// The TCB recovery sets only when the platform clears the standard set but
    /// not the early one, the set Intel publishes and has yet to promote. `None`
    /// in all other cases.
    pub fn early_demotion(&self) -> Option<EarlyDemotion> {
        let (Some((TcbStatus::UpToDate, cleared)), Some((early, demoted))) = (
            self.standard.as_ref()?.status_and_set(),
            self.early.as_ref()?.status_and_set(),
        ) else {
            return None;
        };
        (early != TcbStatus::UpToDate && demoted > cleared)
            .then_some(EarlyDemotion { cleared, demoted })
    }
}

/// `as_of` overrides the evaluation timestamp for collateral validity windows.
/// Intel serves only current collateral, so it makes the served row readable for
/// a saved quote whose snapshot has expired, and leaves the Intel rows
/// present-day verdicts evaluated at a past instant.
pub async fn run(
    static_data: &StaticWebData,
    as_of: Option<u64>,
    requested: Option<EvaluationDataSet>,
) -> anyhow::Result<Report> {
    let dstack = dstack_attestation(static_data)?;
    let quote = &dstack.quote.0;
    // A property of the quote, so it decides every row at once rather than
    // failing one of them.
    let report = *Quote::parse(quote)
        .context("parsing the node's quote")?
        .report
        .as_td10()
        .context("the node's quote does not carry a TDX report")?;
    let now = match as_of {
        Some(timestamp) => timestamp,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock is before the UNIX epoch")?
            .as_secs(),
    };

    let served = collateral_into_dcap(dstack.collateral.clone());
    // An unreachable PCS must not cost the operator the served row, which needs
    // no network at all.
    let verdict_for = async |set: EvaluationDataSet| {
        if requested.is_some_and(|requested_set| requested_set != set) {
            return None;
        }
        Some(match fetch_from_intel(quote, set).await {
            Ok(collateral) => evaluate(quote, &report, &collateral, now),
            Err(err) => TcbVerdict::Rejected(format!("{err:#}")),
        })
    };

    let standard = verdict_for(EvaluationDataSet::Standard).await;
    let early = verdict_for(EvaluationDataSet::Early).await;

    Ok(Report {
        td_report: report,
        served: evaluate(quote, &report, &served, now),
        standard,
        early,
    })
}

async fn fetch_from_intel(
    quote: &[u8],
    evaluation_data_set: EvaluationDataSet,
) -> anyhow::Result<QuoteCollateralV3> {
    let client = CollateralClient::with_default_http(INTEL_PCS_URL)
        .context("building the Intel PCS client")?
        .with_evaluation_data_set(match evaluation_data_set {
            EvaluationDataSet::Standard => TcbEvaluationDataSet::Standard,
            EvaluationDataSet::Early => TcbEvaluationDataSet::Early,
        });
    tokio::time::timeout(PCS_TIMEOUT, client.fetch(quote))
        .await
        .with_context(|| format!("Intel's PCS did not respond within {PCS_TIMEOUT:?}"))?
        .context("fetching collateral from Intel's PCS")
}

/// Every failure mode is per-collateral, so each becomes a [`TcbVerdict::Rejected`]
/// row rather than aborting the other one.
fn evaluate(
    quote: &[u8],
    report: &TDReport10,
    collateral: &QuoteCollateralV3,
    now: u64,
) -> TcbVerdict {
    let claims = match QuoteVerifier::new_prod().verify_with_policy(
        quote,
        collateral,
        now,
        &QuotePolicy::claims_only(now),
    ) {
        Ok(claims) => claims,
        Err(err) => return TcbVerdict::Rejected(err.to_string()),
    };
    let tcb_info = match parse_tcb_info(collateral) {
        Ok(tcb_info) => tcb_info,
        Err(err) => return TcbVerdict::Rejected(err.to_string()),
    };

    // An `UpToDate` platform clears an accepted level, so nothing falls short,
    // and a malformed level DCAP never reached must not overturn its verdict.
    let shortfalls = if claims.tcb.status == TcbStatus::UpToDate {
        Vec::new()
    } else {
        match shortfalls(&tcb_info, &claims.platform.pck, report) {
            Ok(shortfalls) => shortfalls,
            Err(err) => return TcbVerdict::Rejected(err.to_string()),
        }
    };
    TcbVerdict::Verified {
        tcb_info,
        claims,
        shortfalls,
    }
}

/// Every SVN that keeps the platform off Intel's nearest accepted TCB level.
///
/// Explanatory only: the status already says whether the platform clears the
/// bar, this says by how much it misses. Fails on TCB info with no identity for
/// the quote's module, or with an accepted level whose component counts differ
/// from the platform's. Intel's QVL rejects the latter at parse time, but
/// `dcap-qvl` only checks the levels it reaches before a match.
fn shortfalls(
    tcb_info: &TcbInfo,
    pck: &PckIdentity,
    report: &TDReport10,
) -> anyhow::Result<Vec<SvnShortfall>> {
    let tee_tcb_svn = &report.tee_tcb_svn;
    let module = tcb_info
        .tdx_module_identity(tee_tcb_svn)?
        .and_then(|identity| {
            identity
                .tcb_levels
                .iter()
                .filter(|level| level.tcb_status == TcbStatus::UpToDate)
                .min_by_key(|level| level.tcb.isvsvn)?
                .shortfall(tee_tcb_svn)
        });

    // Matching is conjunctive per level: a platform is `UpToDate` only once some
    // single level is cleared on every axis. Reporting the deficit against the
    // nearest level gives a set that is actionable, where a per-axis minimum
    // across levels could describe a level that does not exist.
    let platform = tcb_info
        .tcb_levels
        .iter()
        .filter(|level| level.tcb_status == TcbStatus::UpToDate)
        .map(|level| level.shortfalls(&pck.cpu_svn, pck.pce_svn, Some(tee_tcb_svn)))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .min_by_key(|short| {
            (
                short.len(),
                short
                    .iter()
                    .map(|s| u32::from(s.needs.saturating_sub(s.have)))
                    .sum::<u32>(),
            )
        })
        .unwrap_or_default();

    Ok(module.into_iter().chain(platform).collect())
}

/// The TDX module a quote reports, read out of the first two `tee_tcb_svn`
/// bytes: byte 1 selects which of Intel's `tdxModuleIdentities` entries the
/// module is judged under, spelled `TDX_<byte in hex>`, and byte 0 is that
/// module's ISV SVN. A zero selector means the quote names no identity, and
/// Intel's base `tdxModule` entry applies instead.
///
/// Mirrors the naming rule of [`TcbInfo::tdx_module_identity`], which resolves
/// the identity against TCB info. This reads it off the quote alone, so the
/// module is named even when no collateral verifies.
pub fn tdx_module(tee_tcb_svn: &[u8; 16]) -> (Option<String>, u8) {
    let [isv_svn, selector, ..] = *tee_tcb_svn;
    (
        (selector != 0).then(|| format!("TDX_{selector:02X}")),
        isv_svn,
    )
}

fn dstack_attestation(static_data: &StaticWebData) -> anyhow::Result<&DstackAttestation> {
    match &static_data.tee_participant_info {
        Some(Attestation::Dstack(dstack)) => Ok(dstack),
        Some(Attestation::Mock(_)) => {
            bail!("the node serves a Mock attestation, which carries no TCB status")
        }
        None => bail!("the node serves no attestation, so it is not running in a TEE"),
    }
}

fn parse_tcb_info(collateral: &QuoteCollateralV3) -> anyhow::Result<TcbInfo> {
    serde_json::from_str(&collateral.tcb_info).context("parsing the collateral's TCB info")
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use dcap_qvl::SvnComponent;
    use rstest::rstest;
    use std::assert_matches;
    use test_utils::attestation::{TEST_PUBLIC_DATA_STRING, VALID_ATTESTATION_TIMESTAMP};

    const STANDARD_SET: u32 = 20;
    const EARLY_SET: u32 = 22;

    fn td_report(quote: &[u8]) -> TDReport10 {
        *Quote::parse(quote)
            .expect("fixture quote parses")
            .report
            .as_td10()
            .expect("fixture is a TDX quote")
    }

    fn served() -> (Vec<u8>, QuoteCollateralV3) {
        let static_data: StaticWebData =
            serde_json::from_str(TEST_PUBLIC_DATA_STRING).expect("fixture is valid StaticWebData");
        let dstack =
            dstack_attestation(&static_data).expect("fixture carries a Dstack attestation");
        (
            dstack.quote.0.clone(),
            collateral_into_dcap(dstack.collateral.clone()),
        )
    }

    fn fixture_claims() -> QuoteClaims {
        let (quote, collateral) = served();
        match evaluate(
            &quote,
            &td_report(&quote),
            &collateral,
            VALID_ATTESTATION_TIMESTAMP,
        ) {
            TcbVerdict::Verified { claims, .. } => claims,
            TcbVerdict::Rejected(reason) => {
                panic!("the fixture collateral should verify: {reason}")
            }
        }
    }

    /// Demands one more than the fixture platform reports, on every axis.
    fn demanding_tcb_info(pck: &PckIdentity, report: &TDReport10) -> TcbInfo {
        let mut tcb_info = parse_tcb_info(&served().1).expect("fixture TCB info parses");
        let level = tcb_info
            .tcb_levels
            .first_mut()
            .expect("fixture TCB info has a level");
        level.tcb_status = TcbStatus::UpToDate;
        level.tcb.pce_svn = pck.pce_svn + 1;
        for (component, have) in level.tcb.tdx_components.iter_mut().zip(report.tee_tcb_svn) {
            component.svn = have + 1;
        }
        for (component, have) in level.tcb.sgx_components.iter_mut().zip(pck.cpu_svn) {
            component.svn = have + 1;
        }
        for identity in &mut tcb_info.tdx_module_identities {
            for level in &mut identity.tcb_levels {
                level.tcb_status = TcbStatus::UpToDate;
                level.tcb.isvsvn = tdx_module(&report.tee_tcb_svn).1 + 1;
            }
        }
        tcb_info
    }

    fn verdict(status: TcbStatus, evaluation_data_set: u32) -> TcbVerdict {
        let mut claims = fixture_claims();
        claims.tcb.status = status;
        let mut tcb_info = parse_tcb_info(&served().1).expect("fixture TCB info parses");
        tcb_info.tcb_evaluation_data_number = evaluation_data_set;
        TcbVerdict::Verified {
            tcb_info,
            claims,
            shortfalls: vec![],
        }
    }

    fn rejected() -> TcbVerdict {
        TcbVerdict::Rejected("Intel's PCS did not respond".to_owned())
    }

    fn report(standard: Option<TcbVerdict>, early: Option<TcbVerdict>) -> Report {
        let (quote, _) = served();
        Report {
            td_report: td_report(&quote),
            served: TcbVerdict::Rejected("not under test".to_owned()),
            standard,
            early,
        }
    }

    const DEMOTED_BY_EARLY: Option<EarlyDemotion> = Some(EarlyDemotion {
        cleared: STANDARD_SET,
        demoted: EARLY_SET,
    });

    #[rstest]
    #[case(TcbStatus::UpToDate, TcbStatus::OutOfDate, EARLY_SET, DEMOTED_BY_EARLY)]
    #[case(
        TcbStatus::UpToDate,
        TcbStatus::SWHardeningNeeded,
        EARLY_SET,
        DEMOTED_BY_EARLY
    )]
    #[case(TcbStatus::UpToDate, TcbStatus::UpToDate, EARLY_SET, None)]
    #[case(TcbStatus::OutOfDate, TcbStatus::OutOfDate, EARLY_SET, None)]
    #[case(TcbStatus::OutOfDate, TcbStatus::UpToDate, EARLY_SET, None)]
    #[case(TcbStatus::UpToDate, TcbStatus::OutOfDate, STANDARD_SET, None)]
    fn early_demotion__should_report_the_two_sets_only_when_the_early_one_alone_demotes(
        #[case] standard: TcbStatus,
        #[case] early: TcbStatus,
        #[case] early_set: u32,
        #[case] expected: Option<EarlyDemotion>,
    ) {
        // Given
        let report = report(
            Some(verdict(standard, STANDARD_SET)),
            Some(verdict(early, early_set)),
        );

        // When
        let demotion = report.early_demotion();

        // Then
        assert_eq!(demotion, expected);
    }

    #[rstest]
    #[case(verdict(TcbStatus::UpToDate, STANDARD_SET), true)]
    #[case(verdict(TcbStatus::OutOfDate, STANDARD_SET), false)]
    #[case(verdict(TcbStatus::SWHardeningNeeded, STANDARD_SET), false)]
    #[case(rejected(), false)]
    fn is_up_to_date__should_hold_only_for_a_verified_up_to_date_row(
        #[case] verdict: TcbVerdict,
        #[case] expected: bool,
    ) {
        // When
        let up_to_date = verdict.is_up_to_date();

        // Then
        assert_eq!(up_to_date, expected);
    }

    #[rstest]
    #[case(Some(verdict(TcbStatus::UpToDate, STANDARD_SET)), Some(rejected()))]
    #[case(Some(rejected()), Some(verdict(TcbStatus::OutOfDate, EARLY_SET)))]
    #[case(Some(verdict(TcbStatus::UpToDate, STANDARD_SET)), None)]
    #[case(None, Some(verdict(TcbStatus::OutOfDate, EARLY_SET)))]
    fn early_demotion__should_be_absent_when_a_set_was_not_fetched(
        #[case] standard: Option<TcbVerdict>,
        #[case] early: Option<TcbVerdict>,
    ) {
        // Given
        let report = report(standard, early);

        // When
        let demotion = report.early_demotion();

        // Then
        assert_eq!(demotion, None);
    }

    #[test]
    fn evaluate__should_report_the_platform_the_quote_describes() {
        // Given
        let (quote, collateral) = served();

        // When
        let verdict = evaluate(
            &quote,
            &td_report(&quote),
            &collateral,
            VALID_ATTESTATION_TIMESTAMP,
        );

        // Then
        let TcbVerdict::Verified {
            claims, shortfalls, ..
        } = verdict
        else {
            panic!("the fixture collateral should verify");
        };
        let report = claims.report.as_td10().expect("fixture is a TDX quote");
        assert_eq!(hex::encode_upper(claims.platform.pck.fmspc), "B0C06F000000");
        assert_eq!(
            tdx_module(&report.tee_tcb_svn),
            (Some("TDX_01".to_owned()), 11)
        );
        assert_eq!(claims.platform.pck.pce_svn, 11);
        assert_eq!(claims.tcb.status, TcbStatus::UpToDate);
        assert!(shortfalls.is_empty());
    }

    #[test]
    fn evaluate__should_reject_collateral_that_has_expired() {
        // Given
        let (quote, collateral) = served();
        let long_after_the_collateral_expired = VALID_ATTESTATION_TIMESTAMP + 365 * 24 * 60 * 60;

        // When
        let verdict = evaluate(
            &quote,
            &td_report(&quote),
            &collateral,
            long_after_the_collateral_expired,
        );

        // Then
        assert_matches!(verdict, TcbVerdict::Rejected(_));
    }

    #[test]
    fn shortfalls__should_name_every_svn_the_accepted_level_puts_out_of_reach() {
        // Given
        let claims = fixture_claims();
        let pck = &claims.platform.pck;
        let report = claims.report.as_td10().expect("fixture is a TDX quote");
        let tcb_info = demanding_tcb_info(pck, report);

        // When
        let shortfalls = shortfalls(&tcb_info, pck, report).unwrap();

        // Then
        let components: Vec<_> = shortfalls
            .iter()
            .map(|shortfall| shortfall.component)
            .collect();
        assert!(components.contains(&SvnComponent::TdxModuleIsvSvn));
        assert!(components.contains(&SvnComponent::Tdx(2)));
        assert!(components.contains(&SvnComponent::Sgx(0)));
        assert!(components.contains(&SvnComponent::PceSvn));
        assert!(
            shortfalls
                .iter()
                .all(|shortfall| shortfall.have + 1 == shortfall.needs)
        );
    }

    #[test]
    fn shortfalls__should_leave_the_module_components_to_the_module_identity() {
        // Given
        let claims = fixture_claims();
        let pck = &claims.platform.pck;
        let report = claims.report.as_td10().expect("fixture is a TDX quote");
        let tcb_info = demanding_tcb_info(pck, report);

        // When
        let shortfalls = shortfalls(&tcb_info, pck, report).unwrap();

        // Then
        let components: Vec<_> = shortfalls
            .iter()
            .map(|shortfall| shortfall.component)
            .collect();
        assert!(!components.contains(&SvnComponent::Tdx(0)));
        assert!(!components.contains(&SvnComponent::Tdx(1)));
    }

    #[test]
    fn shortfalls__should_stay_within_one_level_when_several_are_accepted() {
        // Given: two accepted levels the platform clears on different axes, so a
        // per-axis minimum across them would clear both and report nothing.
        let claims = fixture_claims();
        let pck = &claims.platform.pck;
        let report = claims.report.as_td10().expect("fixture is a TDX quote");
        let mut tcb_info = parse_tcb_info(&served().1).expect("fixture TCB info parses");
        let mut level_a = tcb_info.tcb_levels[0].clone();
        level_a.tcb_status = TcbStatus::UpToDate;
        level_a.tcb.sgx_components[0].svn = pck.cpu_svn[0] + 1;
        level_a.tcb.pce_svn = pck.pce_svn - 1;
        let mut level_b = level_a.clone();
        level_b.tcb.sgx_components[0].svn = pck.cpu_svn[0] - 1;
        level_b.tcb.pce_svn = pck.pce_svn + 1;
        tcb_info.tcb_levels = vec![level_a, level_b];

        // When
        let shortfalls = shortfalls(&tcb_info, pck, report).unwrap();

        // Then: exactly one axis short, and it comes from a single level.
        let components: Vec<_> = shortfalls
            .iter()
            .map(|shortfall| shortfall.component)
            .collect();
        assert!(
            components == [SvnComponent::Sgx(0)] || components == [SvnComponent::PceSvn],
            "reported {components:?}"
        );
    }

    #[test]
    fn shortfalls__should_be_empty_when_the_platform_clears_the_bar() {
        // Given
        let claims = fixture_claims();
        let tcb_info = parse_tcb_info(&served().1).unwrap();

        // When
        let shortfalls = shortfalls(
            &tcb_info,
            &claims.platform.pck,
            claims.report.as_td10().expect("fixture is a TDX quote"),
        )
        .unwrap();

        // Then
        assert!(shortfalls.is_empty());
    }

    #[test]
    fn shortfalls__should_fail_when_the_tcb_info_lacks_the_quoted_module_identity() {
        // Given
        let claims = fixture_claims();
        let mut tcb_info = parse_tcb_info(&served().1).unwrap();
        tcb_info.tdx_module_identities.clear();

        // When
        let shortfalls = shortfalls(
            &tcb_info,
            &claims.platform.pck,
            claims.report.as_td10().expect("fixture is a TDX quote"),
        );

        // Then
        let err = shortfalls.unwrap_err();
        assert!(err.to_string().contains("TDX_01"), "{err:#}");
    }

    /// Guards that the `update` parameter still reaches Intel: were it ignored
    /// or renamed, both fetches would return the same set. Fails if Intel ever
    /// promotes the early set before publishing the next one.
    #[tokio::test]
    #[cfg(feature = "external-services-tests")]
    async fn fetch_from_intel__should_serve_an_early_set_ahead_of_the_standard_one() {
        // Given
        let (quote, _) = served();

        // When
        let (standard, early) = tokio::join!(
            fetch_from_intel(&quote, EvaluationDataSet::Standard),
            fetch_from_intel(&quote, EvaluationDataSet::Early),
        );

        // Then
        let set_number = |collateral: anyhow::Result<QuoteCollateralV3>| {
            parse_tcb_info(&collateral.expect("Intel serves the set"))
                .expect("TCB info parses")
                .tcb_evaluation_data_number
        };
        let (standard, early) = (set_number(standard), set_number(early));
        assert!(
            early > standard,
            "early set {early} is not ahead of {standard}"
        );
    }

    #[test]
    fn tdx_module__should_name_no_identity_when_the_quote_selects_none() {
        // Given
        let mut tee_tcb_svn = [0u8; 16];
        tee_tcb_svn[0] = 11;

        // When
        let (identity, isv_svn) = tdx_module(&tee_tcb_svn);

        // Then
        assert_eq!(identity, None);
        assert_eq!(isv_svn, 11);
    }
}
