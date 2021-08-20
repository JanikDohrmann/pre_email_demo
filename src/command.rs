pub mod command {
    extern crate pest;

    use crate::re_encryption::re_encryption::construct_transform_key;
    use crate::target::target::{build_target, Target};
    use pest::Parser;

    #[derive(Parser)]
    #[grammar = "command.pest"]
    struct CommandParser;

    /// Possible commands of the System.
    pub enum Command {
        Start { target: Target },
        Stop,
    }

    /// A function for parsing command strings.
    /// # Arguments
    /// * `text` - A String containing the command to parse
    pub fn parse(text: String) -> Command {
        let pairs = CommandParser::parse(Rule::command_message, text.as_str())
            .unwrap_or_else(|e| panic!("{}", e));

        let mut command = Command::Stop;
        let mut address = String::new();
        let mut re_key = String::new();

        for pair in pairs {
            for inner_pair in pair.into_inner() {
                match inner_pair.as_rule() {
                    Rule::command_start => {
                        for inner_inner_pair in inner_pair.into_inner() {
                            match inner_inner_pair.as_rule() {
                                Rule::address => address = inner_inner_pair.as_str().to_string(),
                                Rule::reKey => re_key = inner_inner_pair.as_str().to_string(),
                                _ => unreachable!(),
                            };
                        }
                        command = Command::Start {
                            target: build_target(
                                address.clone(),
                                construct_transform_key(re_key.clone()),
                            )
                        }
                    },
                    Rule::command_stop => command = Command::Stop,
                    _ => unreachable!(),
                };
            }
        }

        return command;
    }
}

#[cfg(test)]
mod tests {
    use crate::command::command::{parse, Command};
    use crate::re_encryption::re_encryption::deconstruct_transform_key;
    use recrypt::api::*;

    #[test]
    fn parse_start_command_test() {
        let mut recrypt = Recrypt::new();

        let alice_signing_keypair = recrypt.generate_ed25519_key_pair();

        let (alice_priv_key, alice_pub_key) = recrypt.generate_key_pair().unwrap();
        let (bob_priv_key, bob_pub_key) = recrypt.generate_key_pair().unwrap();

        let alice_to_bob_transform_key = recrypt
            .generate_transform_key(&alice_priv_key, &bob_pub_key, &alice_signing_keypair)
            .unwrap();

        let test_re_key = deconstruct_transform_key(alice_to_bob_transform_key.clone());
        let test_address = "test@localhost".to_string();
        let test_string = format!("START\nTA:{}\nRK:{}", test_address, test_re_key);
        let t = parse(test_string);

        match t {
            Command::Start { target } => {
                assert_eq!(test_address, target.address);
                assert_eq!(alice_to_bob_transform_key, target.re_key);
            }
            Command::Stop => {}
        }
    }
}
