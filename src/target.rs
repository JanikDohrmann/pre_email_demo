pub mod target {
    use recrypt::api::TransformKey;

    #[derive(Clone)]
    pub struct Target {
        pub address: String,
        pub re_key: TransformKey
    }

    pub fn build_target(address: String, re_key: TransformKey) -> Target {
        Target {
            address,
            re_key
        }
    }
}