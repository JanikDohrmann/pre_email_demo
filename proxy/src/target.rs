use recrypt::api::TransformKey;

///The target stores information about the re-encryption target.
#[derive(Clone)]
pub struct Target {
    pub address: String,
    pub re_key: TransformKey,
}

/// Creates a target
/// # Arguments
/// * `address` - The address of the target.
/// * `re_key` - The re-encryption key for the target.
/// # Return
/// Returns a target.
pub fn build_target(address: String, re_key: TransformKey) -> Target {
    Target { address, re_key }
}
