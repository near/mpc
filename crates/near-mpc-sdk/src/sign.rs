pub use contract_interface::method_names::SIGN as SIGN_METHOD_NAME;
// response types
pub use contract_interface::types::{
    DomainId, Ed25519Signature, K256AffinePoint, K256Scalar, K256Signature,
    SignatureResponse as SignatureRequestResponse,
};

// raw request arg type
pub use contract_interface::types::{Payload, SignRequestArgs};

#[derive(Debug, Clone)]
pub struct NotSet;

#[derive(Debug, Clone)]
pub struct SignRequestBuilder<Path, Payload, DomainId> {
    path: Path,
    payload: Payload,
    domain_id: DomainId,
}

impl Default for SignRequestBuilder<NotSet, NotSet, NotSet> {
    fn default() -> Self {
        Self::new()
    }
}

impl SignRequestBuilder<NotSet, NotSet, NotSet> {
    pub fn new() -> Self {
        Self {
            path: NotSet,
            payload: NotSet,
            domain_id: NotSet,
        }
    }

    pub fn with_path(self, path: String) -> SignRequestBuilder<String, NotSet, NotSet> {
        SignRequestBuilder {
            path,
            payload: NotSet,
            domain_id: NotSet,
        }
    }
}

impl SignRequestBuilder<String, NotSet, NotSet> {
    pub fn with_payload(
        self,
        payload: impl Into<Payload>,
    ) -> SignRequestBuilder<String, Payload, NotSet> {
        SignRequestBuilder {
            path: self.path,
            payload: payload.into(),
            domain_id: NotSet,
        }
    }
}

impl SignRequestBuilder<String, Payload, NotSet> {
    pub fn with_domain_id(
        self,
        domain_id: impl Into<DomainId>,
    ) -> SignRequestBuilder<String, Payload, DomainId> {
        SignRequestBuilder {
            path: self.path,
            payload: self.payload,
            domain_id: domain_id.into(),
        }
    }
}

impl SignRequestBuilder<String, Payload, DomainId> {
    pub fn build(self) -> SignRequestArgs {
        SignRequestArgs {
            path: self.path,
            payload_v2: self.payload,
            domain_id: self.domain_id,
        }
    }
}

#[cfg(test)]
mod test {
    use bounded_collections::BoundedVec;

    use super::*;

    #[test]
    fn builder_builds_as_expected() {
        // given
        let path = "test_path".to_string();
        let payload = Payload::Ecdsa(BoundedVec::from([1_u8; 32]));
        let domain_id = DomainId(2);

        // when
        let built_sign_request_args = SignRequestBuilder::new()
            .with_path(path.clone())
            .with_payload(payload.clone())
            .with_domain_id(domain_id)
            .build();

        // then
        let expected = SignRequestArgs {
            path,
            payload_v2: payload,
            domain_id,
        };

        assert_eq!(built_sign_request_args, expected);
    }

    #[test]
    fn with_path_sets_expected_value() {
        // given
        let path = "test_path".to_string();

        // when
        let builder = SignRequestBuilder::new().with_path(path.clone());

        // then
        assert_eq!(builder.path, path);
    }

    #[test]
    fn with_payload_sets_expected_value() {
        // given
        let path = "test_path".to_string();
        let payload = Payload::Ecdsa(BoundedVec::from([1_u8; 32]));

        let builder = SignRequestBuilder::new().with_path(path);

        // when
        let builder = builder.with_payload(payload.clone());

        // then
        assert_eq!(builder.payload, payload);
    }

    #[test]
    fn with_domain_id_sets_expected_value() {
        // given
        let path = "test_path".to_string();
        let payload = Payload::Ecdsa(BoundedVec::from([1_u8; 32]));
        let domain_id = 420;

        let builder = SignRequestBuilder::new()
            .with_path(path)
            .with_payload(payload);

        // when
        let builder = builder.with_domain_id(domain_id);

        // then
        assert_eq!(builder.domain_id, DomainId::from(domain_id));
    }
}
