//! Where a node's platform stands against Intel's TCB requirements.
//!
//! Every verdict comes from [`dcap_qvl`], the same verification the contract
//! runs; this module only chooses which collateral it runs against.

use anyhow::{Context as _, bail};
use attestation::attestation::DstackAttestation;
use dcap_qvl::{
    QuoteCollateralV3, Tcb, TcbComponents, TcbLevel, TcbStatus,
    collateral::{CollateralClient, INTEL_PCS_URL},
    policy::{PckIdentity, QuoteClaims, QuotePolicy},
    quote::TDReport10,
    tcb_info::TcbInfo,
    verify::QuoteVerifier,
};
use mpc_attestation::attestation::Attestation;
use mpc_attestation::dcap_conversions::collateral_into_dcap;
use node_types::http_server::StaticWebData;

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
pub enum Outcome {
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
    /// What the node's own boot-time collateral says, which can lag by days.
    pub served: Outcome,
    /// What the contract decides today, against collateral fetched just now.
    pub standard: Outcome,
}

impl Report {
    pub fn is_up_to_date(&self) -> bool {
        matches!(&self.standard, Outcome::Verified { claims, .. } if claims.tcb.status == TcbStatus::UpToDate)
    }
}

pub async fn run(static_data: &StaticWebData) -> anyhow::Result<Report> {
    let dstack = dstack_attestation(static_data)?;
    let quote = &dstack.quote.0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the UNIX epoch")?
        .as_secs();

    // Fetched with no `update` parameter, exactly as the node does, so this is
    // Intel's `standard` set: what the contract verifies against.
    let standard = CollateralClient::with_default_http(INTEL_PCS_URL)
        .context("building the Intel PCS client")?
        .fetch(quote)
        .await
        .context("fetching collateral from Intel's PCS")?;

    let served = collateral_into_dcap(dstack.collateral.clone());
    Ok(Report {
        served: evaluate(quote, &served, now)?,
        standard: evaluate(quote, &standard, now)?,
    })
}

fn evaluate(quote: &[u8], collateral: &QuoteCollateralV3, now: u64) -> anyhow::Result<Outcome> {
    let claims = match QuoteVerifier::new_prod().verify_with_policy(
        quote,
        collateral,
        now,
        &QuotePolicy::claims_only(now),
    ) {
        Ok(claims) => claims,
        Err(err) => return Ok(Outcome::Rejected(err.to_string())),
    };

    let report = *claims
        .report
        .as_td10()
        .context("quote does not carry a TDX report")?;
    let tcb_info = parse_tcb_info(collateral)?;
    let shortfalls = shortfalls(&tcb_info, &claims.platform.pck, &report);

    Ok(Outcome::Verified {
        tcb_info,
        claims,
        shortfalls,
    })
}

/// Every SVN that Intel's accepted levels put out of the platform's reach.
fn shortfalls(tcb_info: &TcbInfo, pck: &PckIdentity, report: &TDReport10) -> Vec<Shortfall> {
    let accepted: Vec<_> = tcb_info
        .tcb_levels
        .iter()
        .filter(|level| level.tcb_status == TcbStatus::UpToDate)
        .collect();
    let short = |component: String, have: u16, needs: u16, remedy| {
        (have < needs).then_some(Shortfall {
            component,
            have,
            needs,
            remedy,
        })
    };

    let (identity, module_svn) = tdx_module(&report.tee_tcb_svn);
    let module = identity.and_then(|identity| {
        let needs = accepted_module_svn(tcb_info, &identity)?;
        short(
            format!("TDX module {identity} ISV SVN"),
            module_svn.into(),
            needs.into(),
            UPDATE_TDX_MODULE,
        )
    });

    // `tee_tcb_svn` opens with the two module bytes, already handled above
    let tdx = report
        .tee_tcb_svn
        .iter()
        .enumerate()
        .skip(2)
        .filter_map(|(index, have)| {
            let needs = component_minimum(&accepted, index, |tcb| &tcb.tdx_components)?;
            short(
                format!("TDX TCB component {index}"),
                (*have).into(),
                needs.into(),
                UPDATE_BIOS,
            )
        });
    let sgx = pck.cpu_svn.iter().enumerate().filter_map(|(index, have)| {
        let needs = component_minimum(&accepted, index, |tcb| &tcb.sgx_components)?;
        short(
            format!("SGX TCB component {index}"),
            (*have).into(),
            needs.into(),
            UPDATE_BIOS,
        )
    });
    let pce = accepted
        .iter()
        .map(|level| level.tcb.pce_svn)
        .min()
        .and_then(|needs| short("PCESVN".to_owned(), pck.pce_svn, needs, UPDATE_BIOS));

    module
        .into_iter()
        .chain(tdx)
        .chain(sgx)
        .chain(pce)
        .collect()
}

/// The `TDX_xx` identity a quote is judged under, and its ISV SVN. A zero
/// selector means it names none, and the base `tdxModule` entry applies.
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

fn component_minimum(
    accepted: &[&TcbLevel],
    index: usize,
    components: impl Fn(&Tcb) -> &Vec<TcbComponents>,
) -> Option<u8> {
    accepted
        .iter()
        .map(|level| Some(components(&level.tcb).get(index)?.svn))
        .collect::<Option<Vec<_>>>()?
        .into_iter()
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
        match evaluate(&quote, &collateral, VALID_ATTESTATION_TIMESTAMP)
            .expect("evaluation should not error")
        {
            Outcome::Verified { claims, .. } => claims,
            Outcome::Rejected(reason) => panic!("the fixture collateral should verify: {reason}"),
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
        let outcome = evaluate(&quote, &collateral, VALID_ATTESTATION_TIMESTAMP)
            .expect("evaluation should not error");

        // Then
        let Outcome::Verified {
            claims, shortfalls, ..
        } = outcome
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
        let outcome = evaluate(&quote, &collateral, long_after_the_collateral_expired)
            .expect("evaluation should not error");

        // Then
        assert_matches!(outcome, Outcome::Rejected(_));
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
