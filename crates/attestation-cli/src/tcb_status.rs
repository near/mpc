//! Where a node's platform stands against Intel's TCB requirements.
//!
//! Every verdict comes from [`dcap_qvl`], the same verification the contract
//! runs; this module only chooses which collateral it runs against.

use std::time::Duration;

use anyhow::{Context as _, bail};
use attestation::attestation::DstackAttestation;
use dcap_qvl::{
    QuoteCollateralV3, TcbLevel, TcbStatus,
    collateral::{CollateralClient, INTEL_PCS_URL},
    policy::{PckIdentity, QuoteClaims, QuotePolicy},
    quote::{Quote, TDReport10},
    tcb_info::TcbInfo,
    verify::QuoteVerifier,
};
use mpc_attestation::{attestation::Attestation, dcap_conversions::collateral_into_dcap};
use node_types::http_server::StaticWebData;

/// Whole-fetch bound on the Intel PCS call. `with_default_http` builds a reqwest
/// client with a 180s timeout of its own, far too long to leave an interactive
/// command hanging on, and `dcap-qvl` keeps that client out of its public API.
/// `tee-authority` bounds the same call the same way.
const PCS_TIMEOUT: Duration = Duration::from_secs(30);

const UPDATE_TDX_MODULE: &str = "update the TDX module (SEAM loader)";
const UPDATE_BIOS: &str = "update BIOS/microcode";

/// One security version number that Intel's accepted TCB level puts out of reach.
#[derive(Debug)]
pub struct Shortfall {
    pub component: String,
    pub have: u16,
    pub needs: u16,
    pub remedy: &'static str,
}

#[expect(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum TcbVerdict {
    /// DCAP's verdict and the TCB info it was reached against. The platform's
    /// own SVNs are in [`QuoteClaims`], under `platform.pck` and `report`.
    Verified {
        tcb_info: TcbInfo,
        claims: QuoteClaims,
        /// Empty when `UpToDate`, and when no level is accepted at all.
        shortfalls: Vec<Shortfall>,
    },
    /// No status at all. Usually expired collateral in a long-running node's
    /// boot-time snapshot.
    Rejected(String),
}

pub struct Report {
    /// Parsed from the quote itself, so the platform's own numbers survive even
    /// when neither collateral verifies.
    pub td_report: TDReport10,
    /// What the node's own boot-time collateral says, which can lag by days.
    pub served: TcbVerdict,
    /// What the contract decides today, against collateral fetched just now.
    pub standard: TcbVerdict,
}

impl Report {
    pub fn is_up_to_date(&self) -> bool {
        matches!(&self.standard, TcbVerdict::Verified { claims, .. } if claims.tcb.status == TcbStatus::UpToDate)
    }
}

/// `as_of` overrides the evaluation timestamp for collateral validity windows.
/// Intel serves only current collateral, so it makes the served row readable for
/// a saved quote whose snapshot has expired, and leaves the Intel row a
/// present-day verdict evaluated at a past instant.
pub async fn run(static_data: &StaticWebData, as_of: Option<u64>) -> anyhow::Result<Report> {
    let dstack = dstack_attestation(static_data)?;
    let quote = &dstack.quote.0;
    // A property of the quote, so it decides both rows at once rather than
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
    let standard = match fetch_standard(quote).await {
        Ok(collateral) => evaluate(quote, &report, &collateral, now),
        Err(err) => TcbVerdict::Rejected(format!("{err:#}")),
    };
    Ok(Report {
        td_report: report,
        served: evaluate(quote, &report, &served, now),
        standard,
    })
}

/// Fetched with no `update` parameter, like the node, so this is Intel's
/// `standard` set: what the contract will decide at the next re-attestation.
/// The node reaches it through its PCCS, so the two can differ in cache
/// freshness.
async fn fetch_standard(quote: &[u8]) -> anyhow::Result<QuoteCollateralV3> {
    let client = CollateralClient::with_default_http(INTEL_PCS_URL)
        .context("building the Intel PCS client")?;
    tokio::time::timeout(PCS_TIMEOUT, client.fetch(quote))
        .await
        .with_context(|| format!("Intel's PCS did not respond within {PCS_TIMEOUT:?}"))?
        .context("fetching collateral from Intel's PCS")
}

/// Both failure modes are per-collateral, so each becomes a [`TcbVerdict::Rejected`]
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

    let shortfalls = shortfalls(&tcb_info, &claims.platform.pck, report);
    TcbVerdict::Verified {
        tcb_info,
        claims,
        shortfalls,
    }
}

/// Every SVN that keeps the platform off Intel's nearest accepted TCB level.
///
/// Explanatory only: the status already says whether the platform clears the
/// bar, this says by how much it misses.
fn shortfalls(tcb_info: &TcbInfo, pck: &PckIdentity, report: &TDReport10) -> Vec<Shortfall> {
    let (identity, module_svn) = tdx_module(&report.tee_tcb_svn);
    let module = identity.and_then(|identity| {
        let needs = accepted_module_svn(tcb_info, &identity)?;
        (module_svn < needs).then(|| Shortfall {
            component: format!("TDX module {identity} ISV SVN"),
            have: module_svn.into(),
            needs: needs.into(),
            remedy: UPDATE_TDX_MODULE,
        })
    });

    // Matching is conjunctive per level: a platform is `UpToDate` only once some
    // single level is cleared on every axis. Reporting the deficit against the
    // nearest level gives a set that is actionable, where a per-axis minimum
    // across levels could describe a level that does not exist.
    let platform = tcb_info
        .tcb_levels
        .iter()
        .filter(|level| level.tcb_status == TcbStatus::UpToDate)
        .map(|level| level_shortfalls(level, pck, report))
        .min_by_key(|short| {
            (
                short.len(),
                short
                    .iter()
                    .map(|s| u32::from(s.needs - s.have))
                    .sum::<u32>(),
            )
        })
        .unwrap_or_default();

    module.into_iter().chain(platform).collect()
}

/// The platform-half SVNs one accepted level puts out of reach. Clearing all of
/// them puts the platform on that level.
///
/// Mirrors the per-level predicate of the private `match_platform_tcb` in
/// `dcap-qvl`'s `src/verify.rs`: a level is cleared only when PCESVN and every
/// SGX and TDX component sit at or above it. The first two TDX components are
/// the module's, so they carry the module remedy.
fn level_shortfalls(level: &TcbLevel, pck: &PckIdentity, report: &TDReport10) -> Vec<Shortfall> {
    let short = |component: String, have: u8, needs: u8, remedy| {
        (have < needs).then_some(Shortfall {
            component,
            have: have.into(),
            needs: needs.into(),
            remedy,
        })
    };
    let tdx = level
        .tcb
        .tdx_components
        .iter()
        .zip(report.tee_tcb_svn)
        .enumerate()
        .filter_map(|(index, (needs, have))| {
            let remedy = if index < 2 {
                UPDATE_TDX_MODULE
            } else {
                UPDATE_BIOS
            };
            short(
                format!("TDX TCB component {index}"),
                have,
                needs.svn,
                remedy,
            )
        });
    let sgx = level
        .tcb
        .sgx_components
        .iter()
        .zip(pck.cpu_svn)
        .enumerate()
        .filter_map(|(index, (needs, have))| {
            short(
                format!("SGX TCB component {index}"),
                have,
                needs.svn,
                UPDATE_BIOS,
            )
        });
    let pce = (pck.pce_svn < level.tcb.pce_svn).then(|| Shortfall {
        component: "PCESVN".to_owned(),
        have: pck.pce_svn,
        needs: level.tcb.pce_svn,
        remedy: UPDATE_BIOS,
    });
    tdx.chain(sgx).chain(pce).collect()
}

/// The TDX module a quote reports, read out of the first two `tee_tcb_svn`
/// bytes: byte 1 selects which of Intel's `tdxModuleIdentities` entries the
/// module is judged under, spelled `TDX_<byte in hex>`, and byte 0 is that
/// module's ISV SVN. A zero selector means the quote names no identity, and
/// Intel's base `tdxModule` entry applies instead.
///
/// Mirrors the private `match_tdx_module_identity` in `dcap-qvl`'s
/// `src/verify.rs`, which surfaces only the converged status, not these.
pub fn tdx_module(tee_tcb_svn: &[u8; 16]) -> (Option<String>, u8) {
    let [isv_svn, selector, ..] = *tee_tcb_svn;
    (
        (selector != 0).then(|| format!("TDX_{selector:02X}")),
        isv_svn,
    )
}

fn accepted_module_svn(tcb_info: &TcbInfo, identity: &str) -> Option<u8> {
    tcb_info
        .tdx_module_identities
        .iter()
        .find(|candidate| candidate.id.eq_ignore_ascii_case(identity))?
        .tcb_levels
        .iter()
        .filter(|level| level.tcb_status == TcbStatus::UpToDate)
        .map(|level| level.tcb.isvsvn)
        .min()
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
    use assert_matches::assert_matches;
    use test_utils::attestation::{TEST_PUBLIC_DATA_STRING, VALID_ATTESTATION_TIMESTAMP};

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
        let shortfalls = shortfalls(&tcb_info, pck, report);

        // Then
        let named: Vec<_> = shortfalls
            .iter()
            .map(|shortfall| shortfall.component.as_str())
            .collect();
        assert!(named.contains(&"TDX module TDX_01 ISV SVN"));
        assert!(named.contains(&"TDX TCB component 2"));
        assert!(named.contains(&"SGX TCB component 0"));
        assert!(named.contains(&"PCESVN"));
        assert!(
            shortfalls
                .iter()
                .all(|shortfall| shortfall.have + 1 == shortfall.needs)
        );
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
        let shortfalls = shortfalls(&tcb_info, pck, report);

        // Then: exactly one axis short, and it comes from a single level.
        let named: Vec<_> = shortfalls
            .iter()
            .map(|shortfall| shortfall.component.as_str())
            .collect();
        assert_eq!(named.len(), 1, "reported {named:?}");
        assert!(named == ["SGX TCB component 0"] || named == ["PCESVN"]);
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
        );

        // Then
        assert!(shortfalls.is_empty());
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
