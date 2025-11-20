pub trait AccountIdExtV1 {
    fn into_v2_account_id(self) -> near_account_id_v2::AccountId;
}

impl AccountIdExtV1 for near_account_id::AccountId {
    fn into_v2_account_id(self) -> near_account_id_v2::AccountId {
        let account_id_string_representation = self.to_string();
        account_id_string_representation
            .parse()
            .expect("Account ID strings are compatible across versions.")
    }
}

pub trait AccountIdExtV2 {
    fn into_v1_account_id(self) -> near_account_id::AccountId;
}

impl AccountIdExtV2 for near_account_id_v2::AccountId {
    fn into_v1_account_id(self) -> near_account_id::AccountId {
        let account_id_string_representation = self.to_string();

        account_id_string_representation
            .parse()
            .expect("Account ID strings are compatible across versions.")
    }
}
