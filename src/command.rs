pub mod command {
    extern crate pest;

    use crate::target::target::{build_target, Target};
    use crate::re_encryption::re_encryption::construct_transform_key;
    use pest::Parser;

    #[derive(Parser)]
    #[grammar = "command.pest"]
    struct CommandParser;

    pub fn parse(text: String) -> Target {
        let pairs = CommandParser::parse(Rule::command_message, text.as_str()).unwrap_or_else(|e| panic!("{}", e));

        let mut address = String::new();
        let mut re_key = String::new();

        for pair in pairs {
            // A pair can be converted to an iterator of the tokens which make it up:
            for inner_pair in pair.into_inner() {
                match inner_pair.as_rule() {
                    Rule::address => address = inner_pair.as_str().to_string(),
                    Rule::reKey => re_key= inner_pair.as_str().to_string(),
                    _ => unreachable!()
                };
            }
        }

        build_target(address, construct_transform_key(re_key))
    }
}

#[cfg(test)]
mod tests {
    use recrypt::api::*;
    use crate::command::command::parse;
    use crate::re_encryption::re_encryption::deconstruct_transform_key;

    #[test]
    fn parse_test() {
        let mut recrypt = Recrypt::new();

        let alice_signing_keypair = recrypt.generate_ed25519_key_pair();

        let (alice_priv_key, alice_pub_key) = recrypt.generate_key_pair().unwrap();
        let (bob_priv_key, bob_pub_key) = recrypt.generate_key_pair().unwrap();

        let alice_to_bob_transform_key = recrypt
            .generate_transform_key(&alice_priv_key, &bob_pub_key, &alice_signing_keypair)
            .unwrap();

        let test_re_key = deconstruct_transform_key(alice_to_bob_transform_key.clone());
        let test_address = "test@localhost".to_string();
        let test_string = format!("TA:{}\nRK:{}", test_address, test_re_key);
        let t = parse(test_string);

        assert_eq!(test_address, t.address);
        assert_eq!(alice_to_bob_transform_key, t.re_key)
    }
}