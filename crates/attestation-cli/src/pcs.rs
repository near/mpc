//! Fetching collateral from Intel's PCS on a chosen TCB evaluation data set.
//!
//! [`dcap_qvl`] builds the collateral URLs internally and always lands on the
//! `standard` set. The HTTP client is the caller's, so the set is chosen here,
//! by rewriting the `update` query parameter on the way out.

use std::{collections::BTreeMap, time::Duration};

use dcap_qvl::http::{HttpClient, HttpResponse};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcbEvaluationDataSet {
    Standard,
    Early,
}

pub struct IntelPcsHttpClient {
    client: reqwest::Client,
    evaluation_data_set: TcbEvaluationDataSet,
}

impl IntelPcsHttpClient {
    pub fn new(
        evaluation_data_set: TcbEvaluationDataSet,
        timeout: Duration,
    ) -> reqwest::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder().timeout(timeout).build()?,
            evaluation_data_set,
        })
    }
}

impl HttpClient for IntelPcsHttpClient {
    async fn get(&self, url: &str) -> anyhow::Result<HttpResponse> {
        let response = self
            .client
            .get(with_evaluation_data_set(url, self.evaluation_data_set))
            .send()
            .await?;
        Ok(HttpResponse {
            status: response.status().as_u16(),
            headers: response
                .headers()
                .iter()
                .map(|(name, value)| Ok((name.as_str().to_owned(), value.to_str()?.to_owned())))
                .collect::<anyhow::Result<BTreeMap<_, _>>>()?,
            body: response.bytes().await?.to_vec(),
        })
    }
}

fn with_evaluation_data_set(url: &str, evaluation_data_set: TcbEvaluationDataSet) -> String {
    let Some(mut parsed) = url::Url::parse(url).ok().filter(|parsed| {
        evaluation_data_set == TcbEvaluationDataSet::Early
            && (parsed.path().ends_with("/tcb") || parsed.path().ends_with("/qe/identity"))
    }) else {
        return url.to_owned();
    };

    let kept: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(name, _)| name != "update")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    parsed
        .query_pairs_mut()
        .clear()
        .extend_pairs(kept)
        .append_pair("update", "early");
    parsed.into()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    const COLLATERAL_URLS: [&str; 4] = [
        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=00A06D080000",
        "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity?update=standard",
        "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der",
        "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
    ];

    #[test]
    fn with_evaluation_data_set__should_leave_every_url_alone_for_the_standard_set() {
        // When
        let requested = COLLATERAL_URLS
            .map(|url| with_evaluation_data_set(url, TcbEvaluationDataSet::Standard));

        // Then
        assert_eq!(requested, COLLATERAL_URLS);
    }

    #[test]
    fn with_evaluation_data_set__should_switch_only_the_set_bearing_endpoints_to_early() {
        // When
        let requested =
            COLLATERAL_URLS.map(|url| with_evaluation_data_set(url, TcbEvaluationDataSet::Early));

        // Then
        assert_eq!(
            requested,
            [
                "https://api.trustedservices.intel.com/tdx/certification/v4/tcb\
                 ?fmspc=00A06D080000&update=early",
                "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity\
                 ?update=early",
                COLLATERAL_URLS[2],
                COLLATERAL_URLS[3],
            ]
        );
    }
}
