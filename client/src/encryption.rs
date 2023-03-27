use recrypt::api::*;
use recrypt::nonemptyvec::NonEmptyVec;
use recrypt::api::EncryptedValue::{TransformedValue, EncryptedOnceValue};

/// The length of an EncryptedOnceValue in byte
const ENCRYPTED_ONCE_VALUE_LENGTH: usize = 576;

/// The length of a public key in byte
const PUBLIC_KEY_SIZE: usize = 64;

/// The size of a message in byte
const MESSAGE_SIZE: usize = 384;

/// The size of the public signing key in byte
const PUBLIC_SIGNING_KEY_SIZE: usize = 32;

/// Converts an String into an EncryptedValue. The incoming text must have the form:
/// xxx xxx xxx ... where x is a digit. The triplets of digits represent one byte of the encrypted text.
/// # Arguments
/// * `text` - The String to convert. The text must have the form:
/// xxx xxx xxx ... where x is a digit. The triplets of digits represent one byte of the encrypted text.
/// # Return
/// Returns an EncryptedValue build from the input text. The EncryptedValue can be either en EncryptedOnceValue or a TransformedValue.
pub fn construct_enc_value(text: String) -> EncryptedValue {
    let text_vec = convert_to_vec_u8(text);
    if text_vec.len() == ENCRYPTED_ONCE_VALUE_LENGTH {
        println!("Der Ciphertext wird in einen EncryptedOnceValue konvertiert, da die Nachricht nur einmal verschlüsselt wurde.\nDadurch beträgt die Länge des Ciphertexts genau 576 Byte. Durch die Umschlüsselung wird der Ciphertext länger.");
        construct_enc_once_value(text_vec)
    } else {
        println!("Der Ciphertext wird in einen TransformedValue konvertiert, da die Nachricht bereits mindestens einmal umgeschlüsselt wurde.\n Die Länge des Ciphertext beträgt {} Bytes und der Ciphertext wird durch die Umschlüsselung weiter anwachsen.", text_vec.len());
        construct_transformed_value(text_vec)
    }
}

/// Creates an EncryptedOnceValue from an vector of bytes.
pub fn construct_enc_once_value(text_vec: Vec<u8>) -> EncryptedValue {
    let epk_split = text_vec.split_at(PUBLIC_KEY_SIZE);
    let epk = construct_public_key(epk_split.0).unwrap();

    let msg_split = epk_split.1.split_at(MESSAGE_SIZE);
    let msg = EncryptedMessage::new_from_slice(msg_split.0).unwrap();

    let ah_split = msg_split.1.split_at(32);
    let ah = AuthHash::new_from_slice(ah_split.0).unwrap();

    let psk_split = ah_split.1.split_at(PUBLIC_SIGNING_KEY_SIZE);
    let psk = PublicSigningKey::new_from_slice(psk_split.0).unwrap();

    let s = Ed25519Signature::new_from_slice(psk_split.1).unwrap();

    let enc = recrypt::api::EncryptedValue::EncryptedOnceValue {
        ephemeral_public_key: epk,
        encrypted_message: msg,
        auth_hash: ah,
        public_signing_key: psk,
        signature: s,
    };

    return enc;
}

/// Creates an TransformedValue from an vector of bytes.
pub fn construct_transformed_value(text_vec: Vec<u8>) -> EncryptedValue {
    let epk_split = text_vec.split_at(PUBLIC_KEY_SIZE);
    let epk = construct_public_key(epk_split.0).unwrap();

    let msg_split = epk_split.1.split_at(MESSAGE_SIZE);
    let msg = EncryptedMessage::new_from_slice(msg_split.0).unwrap();

    let ah_split = msg_split.1.split_at(32);
    let ah = AuthHash::new_from_slice(ah_split.0).unwrap();

    let mut tb_split = ah_split.1;
    let split = tb_split.split_at(896);
    let tb_vec = NonEmptyVec::new_first(construct_transform_block(split.0.to_vec()));
    tb_split = split.1;
    while tb_split.len() > 896 {
        let split = tb_split.split_at(896);
        tb_vec.concat(&NonEmptyVec::new_first(construct_transform_block(
            split.0.to_vec(),
        )));
        tb_split = split.1;
    }

    let psk_split = tb_split.split_at(PUBLIC_SIGNING_KEY_SIZE);
    let psk = PublicSigningKey::new_from_slice(psk_split.0).unwrap();

    let s = Ed25519Signature::new_from_slice(psk_split.1).unwrap();

    let enc = recrypt::api::EncryptedValue::TransformedValue {
        ephemeral_public_key: epk,
        encrypted_message: msg,
        auth_hash: ah,
        transform_blocks: tb_vec,
        public_signing_key: psk,
        signature: s,
    };

    return enc;
}

/// Determines whether an encrypted value is an EncryptedOnceValue or a TransformedValue.
/// Deconstructs the encrypted value into s string representation of the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent an byte of the encrypted value.
/// # Arguments
/// * `encrypted_value` - The EncryptedValue that should be deconstructed.
/// # Return
/// Returns a String representation of the EncryptedValue.
pub fn deconstruct_encrypted_value(encrypted_value: EncryptedValue) -> String {
    match encrypted_value {
        EncryptedValue::EncryptedOnceValue { .. } => deconstruct_encrypted_once_value(encrypted_value),
        EncryptedValue::TransformedValue { .. } => deconstruct_transformed_value(encrypted_value),
    }
}

/// Converts an EncryptedOnceValue into an string of bytes. The string is in the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent an byte of the encrypted value.
pub fn deconstruct_encrypted_once_value(encrypted_value: EncryptedValue) -> String {
    let mut vec = Vec::new();
    if let EncryptedOnceValue {
        ephemeral_public_key,
        encrypted_message,
        auth_hash,
        public_signing_key,
        signature,
    } = encrypted_value
    {
        vec.append(&mut deconstruct_public_key(ephemeral_public_key));
        for x in encrypted_message.bytes() {
            vec.push(*x)
        }
        for x in auth_hash.bytes() {
            vec.push(*x)
        }
        for x in public_signing_key.bytes() {
            vec.push(*x)
        }
        for x in signature.bytes() {
            vec.push(*x)
        }
    }
    convert_to_string(vec)
}

/// Converts an TransformedValue into an string of bytes. The string is in the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent an byte of the encrypted value.
pub fn deconstruct_transformed_value(transformed_value: EncryptedValue) -> String {
    let mut vec = Vec::new();
    if let TransformedValue {
        ephemeral_public_key,
        encrypted_message,
        auth_hash,
        transform_blocks,
        public_signing_key,
        signature,
    } = transformed_value
    {
        vec.append(&mut deconstruct_public_key(ephemeral_public_key));
        for x in encrypted_message.bytes() {
            vec.push(*x)
        }
        for x in auth_hash.bytes() {
            vec.push(*x)
        }
        for b in transform_blocks.as_vec() {
            vec.append(&mut deconstruct_transform_block(b))
        }
        for x in public_signing_key.bytes() {
            vec.push(*x)
        }
        for x in signature.bytes() {
            vec.push(*x)
        }
    }
    return convert_to_string(vec);
}

/// Constructs a public key from a split of byte values.
pub fn construct_public_key(split: &[u8]) -> Option<PublicKey> {
    if split.len() < 32 { return Option::None; }
    let pk_bytes = split.split_at(32);
    let public_key = PublicKey::new_from_slice(pk_bytes);

    return if public_key.is_ok() {
        Option::Some(public_key.unwrap())
    } else {
        Option::None
    }
}

/// Deconstructs a public key into a vector of bytes.
pub fn deconstruct_public_key(public_key: PublicKey) -> Vec<u8> {
    let mut vec = Vec::new();

    let k = public_key.bytes_x_y();
    let lk = k.0;
    let rk = k.1;
    for x in lk {
        vec.push(*x)
    }
    for x in rk {
        vec.push(*x)
    }

    return vec;
}

/// Constructs a private key from a split of byte values.
pub fn construct_private_key(split: &[u8]) -> Option<PrivateKey> {
    let private_key = PrivateKey::new_from_slice(split);

    return if private_key.is_ok() {
        Option::Some(private_key.unwrap())
    } else {
        Option::None
    }
}

/// Deconstructs a private key into a vector of bytes.
pub fn deconstruct_private_key(private_key: PrivateKey) -> Vec<u8> {
    let mut vec = Vec::new();

    for x in private_key.bytes() {
        vec.push(*x)
    }

    return vec;
}

/// Deconstructs a TransformBlock into a vector of bytes.
fn deconstruct_transform_block(transform_block: TransformBlock) -> Vec<u8> {
    let mut vec = Vec::new();

    vec.append(&mut deconstruct_public_key(*transform_block.public_key()));

    for x in transform_block.encrypted_temp_key().bytes() {
        vec.push(*x)
    }

    vec.append(&mut deconstruct_public_key(
        *transform_block.random_transform_public_key(),
    ));

    for x in transform_block
        .encrypted_random_transform_temp_key()
        .bytes()
    {
        vec.push(*x)
    }

    return vec;
}

/// Constructs an TransformBlock from a vector of bytes.
fn construct_transform_block(vec: Vec<u8>) -> TransformBlock {
    let pk_split = vec.split_at(PUBLIC_KEY_SIZE);
    let pk = construct_public_key(pk_split.0).unwrap();

    let etk_split = pk_split.1.split_at(384);
    let etk = EncryptedTempKey::new_from_slice(etk_split.0).unwrap();

    let rtpk_split = etk_split.1.split_at(PUBLIC_KEY_SIZE);
    let rtpk = construct_public_key(rtpk_split.0).unwrap();

    let erttk_split = rtpk_split.1.split_at(384);
    let erttk = EncryptedTempKey::new_from_slice(erttk_split.0).unwrap();

    TransformBlock::new(&pk, &etk, &rtpk, &erttk).unwrap()
}

/// Converts a TransformKey into a string of the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent an byte.
pub fn deconstruct_transform_key(transform_key: TransformKey) -> String {
    let mut vec = Vec::new();

    vec.append(&mut deconstruct_public_key(
        *transform_key.ephemeral_public_key(),
    ));

    vec.append(&mut deconstruct_public_key(*transform_key.to_public_key()));

    for x in transform_key.encrypted_temp_key().bytes() {
        vec.push(*x)
    }

    for x in transform_key.hashed_temp_key().bytes() {
        vec.push(*x)
    }

    for x in transform_key.public_signing_key().bytes() {
        vec.push(*x)
    }

    for x in transform_key.signature().bytes() {
        vec.push(*x)
    }

    convert_to_string(vec)
}

/// Converts  a string of the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent a byte into a TransformKey.
pub fn construct_transform_key(key: String) -> TransformKey {
    let vec = convert_to_vec_u8(key);

    let epk_split = vec.split_at(64);
    let ephemeral_public_key = construct_public_key(epk_split.0).unwrap();

    let tpk_split = epk_split.1.split_at(64);
    let to_public_key = construct_public_key(tpk_split.0).unwrap();

    let etk_split = tpk_split.1.split_at(384);
    let encrypted_temp_key = EncryptedTempKey::new_from_slice(etk_split.0).unwrap();

    let htk_split = etk_split.1.split_at(128);
    let hashed_temp_key = HashedValue::new_from_slice(htk_split.0).unwrap();

    let psk_split = htk_split.1.split_at(32);
    let public_signing_key = PublicSigningKey::new_from_slice(psk_split.0).unwrap();

    let signature = Ed25519Signature::new_from_slice(psk_split.1).unwrap();
    TransformKey::new(
        ephemeral_public_key,
        to_public_key,
        encrypted_temp_key,
        hashed_temp_key,
        public_signing_key,
        signature,
    )
}

/// Converts a string of the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent a byte of the key into a SigningKeypair.
pub fn construct_signing_keypair(key: String) -> Option<SigningKeypair> {
    let vec = convert_to_vec_u8(key);
    let signing_keypair = SigningKeypair::from_byte_slice(&*vec);

    return if signing_keypair.is_ok() {
        Option::Some(signing_keypair.unwrap())
    } else {
        Option::None
    }
}

/// Converts a SigningKeypair into a string of the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent a byte of the key
pub fn deconstruct_signing_keypair(key: SigningKeypair) -> String {
    let mut vec = Vec::new();
    for x in key.bytes() {
        vec.push(*x)
    }
    convert_to_string(vec)
}

/// Converts a string into a Plaintext for encryption.
pub fn construct_plaintext(mut text: String) -> Plaintext {
    while text.len() < MESSAGE_SIZE {
        text.push_str(" ");
    }
    let vec = text.as_bytes();
    Plaintext::new_from_slice(vec).unwrap()
}

/// Converts an plaintext into an string.
pub fn deconstruct_plaintext(plaintext: Plaintext) -> String {
    let mut vec = Vec::new();
    for x in plaintext.bytes() {
        vec.push(*x)
    }
    String::from_utf8(vec).unwrap().trim().to_string()
}

/// Converts an vector of bytes into an string of the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent an byte.
pub fn convert_to_string(vec: Vec<u8>) -> String {
    let mut result = String::new();
    for v in vec {
        let mut s;
        if v < 10 {
            s = "00".to_string();
            s.push_str(&v.to_string());
        } else if v < 100 {
            s = "0".to_string();
            s.push_str(&v.to_string());
        } else {
            s = v.to_string();
        }
        result.push_str(&s);
        result.push_str(" ");
    }

    return result;
}

/// Converts a string of the form:
/// xxx xxx xxx ...  where x is a digit and the triplets xxx represent an byte into a vector of bytes.
pub fn convert_to_vec_u8(s: String) -> Vec<u8> {
    let mut vec = Vec::new();
    let blocks = s.split(" ").collect::<Vec<_>>();
    for block in blocks {
        let parsed_block = block.parse::<u8>();
        if parsed_block.is_ok() {
            vec.push(parsed_block.unwrap());
        }
    }
    vec
}

#[cfg(test)]
mod tests {
    use crate::message::build_message;
    use crate::encryption::{construct_enc_value, deconstruct_encrypted_value, deconstruct_plaintext, construct_plaintext};
    use crate::target::build_target;
    use recrypt::api::*;

    ///Test for constructing and deconstructing of a plaintext
    #[test]
    fn plaintext_test() {
        let original_string = "Test";

        let plaintext = construct_plaintext(original_string.to_string());

        let deconstructed_string = deconstruct_plaintext(plaintext);

        assert_eq!(original_string, deconstructed_string)
    }

    /// Test for encryption of plaintext
    #[test]
    fn enc_dec_test() {
        let recrypt = Recrypt::new();

        let original_plaintext = recrypt.gen_plaintext();

        let origin_signing_keypair = recrypt.generate_ed25519_key_pair();

        let (alice_priv_key, alice_pub_key) = recrypt.generate_key_pair().unwrap();

        let encrypted_val = recrypt
            .encrypt(&original_plaintext, &alice_pub_key, &origin_signing_keypair)
            .unwrap();

        let enc_string = deconstruct_encrypted_value(encrypted_val);

        let enc = construct_enc_value(enc_string);

        let decrypted_plaintext = recrypt.decrypt(enc, &alice_priv_key).unwrap();

        assert_eq!(original_plaintext, decrypted_plaintext);
    }
}