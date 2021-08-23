pub mod re_encryption {
    use crate::message::message::{build_message, Message};
    use crate::target::target::Target;
    use recrypt::api::*;
    use recrypt::nonemptyvec::NonEmptyVec;

    pub fn re_encrypt(target: Target, message: Message, singing_keys: SigningKeypair) -> Message {
        let enc_value = create_enc_value(message.text);

        let recrypt = Recrypt::new();
        let transformed_value = recrypt
            .transform(enc_value, target.re_key, &singing_keys)
            .unwrap();

        let text = create_transformed_value_string(transformed_value);
        return build_message(message.subject, message.from, text);
    }

    pub fn create_enc_value(text: String) -> EncryptedValue {
        let text_vec = convert_to_vec_u8(text);
        //println!("{}", text_vec.len());
        if text_vec.len() == 576 {
            //println!("Once");
            create_enc_once_value(text_vec)
        } else {
            //println!("Transformed");
            create_transformed_value(text_vec)
        }
    }

    fn create_enc_once_value(text_vec: Vec<u8>) -> EncryptedValue {
        let epk_split = text_vec.split_at(64);
        let epk_bytes = epk_split.0.split_at(32);
        let epk = PublicKey::new_from_slice(epk_bytes).unwrap();

        let msg_split = epk_split.1.split_at(384);
        let msg = EncryptedMessage::new_from_slice(msg_split.0).unwrap();

        let ah_split = msg_split.1.split_at(32);
        let ah = AuthHash::new_from_slice(ah_split.0).unwrap();

        let psk_split = ah_split.1.split_at(32);
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

    fn create_transformed_value(text_vec: Vec<u8>) -> EncryptedValue {
        let epk_split = text_vec.split_at(64);
        let epk = construct_public_key(epk_split.0);

        let msg_split = epk_split.1.split_at(384);
        let msg = EncryptedMessage::new_from_slice(msg_split.0).unwrap();

        let ah_split = msg_split.1.split_at(32);
        let ah = AuthHash::new_from_slice(ah_split.0).unwrap();

        let mut tb_split = ah_split.1;
        let split = tb_split.split_at(896);
        let mut tb_vec = NonEmptyVec::new_first(construct_transform_block(split.0.to_vec()));
        tb_split = split.1;
        while tb_split.len() > 896 {
            let split = tb_split.split_at(896);
            tb_vec.concat(&NonEmptyVec::new_first(construct_transform_block(
                split.0.to_vec(),
            )));
            tb_split = split.1;
        }

        let psk_split = tb_split.split_at(32);
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

    pub fn create_encrypted_once_value_string(encrypted_once_value: EncryptedValue) -> String {
        let mut vec = Vec::new();
        if let recrypt::api::EncryptedValue::EncryptedOnceValue {
            ephemeral_public_key,
            encrypted_message,
            auth_hash,
            public_signing_key,
            signature,
        } = encrypted_once_value
        {
            let k = ephemeral_public_key.bytes_x_y();
            let lk = k.0;
            let rk = k.1;
            for x in lk {
                vec.push(*x)
            }
            for x in rk {
                vec.push(*x)
            }

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

    pub fn create_transformed_value_string(transformed_value: EncryptedValue) -> String {
        let mut vec = Vec::new();
        if let recrypt::api::EncryptedValue::TransformedValue {
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

    fn construct_public_key(split: &[u8]) -> PublicKey {
        let pk_bytes = split.split_at(32);
        let public_key = PublicKey::new_from_slice(pk_bytes).unwrap();
        return public_key;
    }

    fn deconstruct_public_key(public_key: PublicKey) -> Vec<u8> {
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

    fn construct_transform_block(vec: Vec<u8>) -> TransformBlock {
        let pk_split = vec.split_at(64);
        let pk = construct_public_key(pk_split.0);

        let etk_split = pk_split.1.split_at(384);
        let etk = EncryptedTempKey::new_from_slice(etk_split.0).unwrap();

        let rtpk_split = etk_split.1.split_at(64);
        let rtpk = construct_public_key(rtpk_split.0);

        let erttk_split = rtpk_split.1.split_at(384);
        let erttk = EncryptedTempKey::new_from_slice(erttk_split.0).unwrap();

        TransformBlock::new(&pk, &etk, &rtpk, &erttk).unwrap()
    }

    pub fn convert_to_string(vec: Vec<u8>) -> String {
        let mut result = String::new();
        for v in vec {
            let mut s = String::new();
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

    pub fn construct_plaintext(mut text: String) -> Plaintext {
        while text.len() < 384 {
            text.push_str(" ");
        }
        let mut vec = text.as_bytes();
        Plaintext::new_from_slice(vec).unwrap()
    }

    pub fn deconstruct_plaintext(plaintext: Plaintext) -> String {
        let mut vec = Vec::new();
        for x in plaintext.bytes() {
            vec.push(*x)
        }
        String::from_utf8(vec).unwrap().trim().to_string()
    }

    pub fn deconstruct_transform_key(transform_key: TransformKey) -> String {
        let mut vec = Vec::new();

        vec.append(&mut deconstruct_public_key(*transform_key.ephemeral_public_key()));

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

    pub fn construct_transform_key(key: String) -> TransformKey {
        let vec = convert_to_vec_u8(key);

        let epk_split = vec.split_at(64);
        let ephemeral_public_key = construct_public_key(epk_split.0);

        let tpk_split = epk_split.1.split_at(64);
        let to_public_key = construct_public_key(tpk_split.0);

        let etk_split = tpk_split.1.split_at(384);
        let encrypted_temp_key = EncryptedTempKey::new_from_slice(etk_split.0).unwrap();

        let htk_split = etk_split.1.split_at(128);
        let hashed_temp_key = HashedValue::new_from_slice(htk_split.0).unwrap();

        let psk_split = htk_split.1.split_at(32);
        let public_signing_key = PublicSigningKey::new_from_slice(psk_split.0).unwrap();

        let signature = Ed25519Signature::new_from_slice(psk_split.1).unwrap();
        TransformKey::new(ephemeral_public_key, to_public_key, encrypted_temp_key, hashed_temp_key, public_signing_key, signature)
    }

    pub fn construct_signing_keypair(key: String) -> SigningKeypair {
        let vec = convert_to_vec_u8(key);
        SigningKeypair::from_byte_slice(&*vec).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::message::message::build_message;
    use crate::re_encryption::re_encryption::{
        convert_to_string, convert_to_vec_u8, create_enc_value, create_encrypted_once_value_string,
        re_encrypt,
    };
    use crate::re_encryption::*;
    use crate::target::target::build_target;
    use recrypt::api::*;
    use recrypt::api::{EncryptedMessage, EncryptedValue};

    #[test]
    fn enc_dec_test() {
        // create a new recrypt
        let mut recrypt = Recrypt::new();

        // generate a plaintext to encrypt
        let original_plaintext = recrypt.gen_plaintext();

        // generate signing keys
        let origin_signing_keypair = recrypt.generate_ed25519_key_pair();
        let alice_signing_keypair = recrypt.generate_ed25519_key_pair();

        // generate a public/private keypair to encrypt the data to initially.
        let (alice_priv_key, alice_pub_key) = recrypt.generate_key_pair().unwrap();
        let (bob_priv_key, bob_pub_key) = recrypt.generate_key_pair().unwrap();

        // generate a transform key that will change which private key can decrypt the data
        let alice_to_bob_transform_key = recrypt
            .generate_transform_key(&alice_priv_key, &bob_pub_key, &alice_signing_keypair)
            .unwrap();

        // encrypt the data to `initial_pub_key`!
        let encrypted_val = recrypt
            .encrypt(&original_plaintext, &alice_pub_key, &origin_signing_keypair)
            .unwrap();

        let enc_string = create_encrypted_once_value_string(encrypted_val);

        let enc = create_enc_value(enc_string);

        let decrypted_plaintext = recrypt.decrypt(enc, &alice_priv_key).unwrap();

        assert_eq!(original_plaintext, decrypted_plaintext);
    }

    #[test]
    fn transform_once_test() {
        // create a new recrypt
        let mut recrypt = Recrypt::new();

        // generate a plaintext to encrypt
        let original_plaintext = recrypt.gen_plaintext();

        // generate signing keys
        let origin_signing_keypair = recrypt.generate_ed25519_key_pair();
        let alice_signing_keypair = recrypt.generate_ed25519_key_pair();

        // generate a public/private keypair to encrypt the data to initially.
        let (alice_priv_key, alice_pub_key) = recrypt.generate_key_pair().unwrap();
        let (bob_priv_key, bob_pub_key) = recrypt.generate_key_pair().unwrap();

        // generate a transform key that will change which private key can decrypt the data
        let alice_to_bob_transform_key = recrypt
            .generate_transform_key(&alice_priv_key, &bob_pub_key, &alice_signing_keypair)
            .unwrap();

        // encrypt the data to `initial_pub_key`!
        let encrypted_val = recrypt
            .encrypt(&original_plaintext, &alice_pub_key, &origin_signing_keypair)
            .unwrap();

        let enc_string = create_encrypted_once_value_string(encrypted_val);

        let transformed_message = re_encrypt(
            build_target("".to_string(), alice_to_bob_transform_key),
            build_message("".to_string(), "".to_string(), enc_string),
            alice_signing_keypair,
        );

        let enc = create_enc_value(transformed_message.text);

        let decrypted_plaintext = recrypt.decrypt(enc, &bob_priv_key).unwrap();

        assert_eq!(original_plaintext, decrypted_plaintext);
    }
}
