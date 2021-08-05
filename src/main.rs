use crate::message_loader::message_loader::parse_message;
use crate::message_transmitter::message_transmitter::send_message;
use crate::target::target::build_target;
use recrypt::api::TransformKey;

use recrypt::prelude::*;
use crate::message::message::build_message;

mod message;
mod message_loader;
mod target;
mod command;
mod message_transmitter;
mod re_encryption;

#[macro_use]
extern crate pest_derive;

fn main() {

    // create a new recrypt
    let mut recrypt = Recrypt::new();

// generate a plaintext to encrypt
    let pt = recrypt.gen_plaintext();

// generate signing keys
    let signing_keypair= recrypt.generate_ed25519_key_pair();

// generate a public/private keypair to encrypt the data to initially.
    let (initial_priv_key, initial_pub_key) = recrypt.generate_key_pair().unwrap();

// encrypt the data to `initial_pub_key`!
    let encrypted_val = recrypt.encrypt(&pt, &initial_pub_key, &signing_keypair).unwrap();

// generate a second public/private keypair as the target of the transform.
// after applying the transform, `target_priv_key` will be able to decrypt the data!
    let (target_priv_key, target_pub_key) = recrypt.generate_key_pair().unwrap();

// generate a transform key that will change which private key can decrypt the data
    let initial_to_target_transform_key = recrypt.generate_transform_key(
        &initial_priv_key,
        &target_pub_key,
        &signing_keypair).unwrap();

    send_message(build_target("janik.dohrmann@gmx.de".parse().unwrap(), initial_to_target_transform_key), build_message("PRE Test".parse().unwrap(), "".to_string(), "Dies ist ein Test!".to_string()), "janik.dohrmann@gmx.de".to_string());
}
