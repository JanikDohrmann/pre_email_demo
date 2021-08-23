extern crate imap;

use crate::message_loader::message_loader::{connect, load_message, load_unseen_messages};
use crate::message_transmitter::message_transmitter::{send_message, smtp_connect};
use crate::target::target::{build_target, Target};

use crate::message::message::build_message;
use std::{thread, time};
use lettre::{EmailAddress, Envelope, SendableEmail, SmtpClient, Transport};
use recrypt::prelude::*;
use std::io;
use std::net::TcpStream;
use crate::re_encryption::re_encryption::{construct_signing_keypair, re_encrypt};
use crate::command::command::{parse, Command};

mod command;
mod message;
mod message_loader;
mod message_transmitter;
mod re_encryption;
mod target;

#[macro_use]
extern crate pest_derive;

/// Main funktion of the proxy. Contains the main loop of the system.
fn main() {
    println!("Welcome to the proxy re-encryption demonstration!");
    println!("\n\nFirst we will configure this proxy.\nWe will start with the connection to the IMAP server.");
    println!("\nPlease enter the address of the IMAP server:");
    let mut imap_address = String::new();
    io::stdin().read_line(&mut imap_address).expect("");
    let imap_address =imap_address.replace("\n", "");

    let mut imap_port = 0;
    while imap_port==0 {
        println!("Please enter the port on wich your IMAP server is listening:");
        let mut imap_port_string = String::new();
        io::stdin().read_line(&mut imap_port_string).expect("");
        let parsed_block = imap_port_string.replace("\n", "").parse::<u16>();
        if parsed_block.is_ok() {
            imap_port = parsed_block.unwrap();
        }
    }

    println!("Please enter the username for the IMAP server:");
    let mut imap_username = String::new();
    io::stdin().read_line(&mut imap_username).expect("");
    let imap_username = imap_username.replace("\n", "");

    println!("Please enter the password for the IMAP server:");
    let mut imap_password = String::new();
    io::stdin().read_line(&mut imap_password).expect("");
    let imap_password = imap_password.replace("\n", "");

    println!("Now we configure the connection to the SMTP server.");
    println!("Please enter the address of the SMTP server:");
    let mut smtp_address = String::new();
    io::stdin().read_line(&mut smtp_address).expect("");
    let smtp_address =smtp_address.replace("\n", "");

    let mut smtp_port = 0;
    while smtp_port==0 {
        println!("Please enter the port on wich your SMTP server is listening:");
        let mut smtp_port_string = String::new();
        io::stdin().read_line(&mut smtp_port_string).expect("");
        let parsed_block = smtp_port_string.replace("\n", "").parse::<u16>();
        if parsed_block.is_ok() {
            smtp_port = parsed_block.unwrap();
        }
    }

    println!("Please enter the username for the SMTP server:");
    let mut smtp_username = String::new();
    io::stdin().read_line(&mut smtp_username).expect("");
    let smtp_username = smtp_username.replace("\n", "");

    println!("Please enter the password for the SMTP server:");
    let mut smtp_password = String::new();
    io::stdin().read_line(&mut smtp_password).expect("");
    let smtp_password = smtp_password.replace("\n", "");

    println!("In the last step we are configuring the re encryption");
    println!("Please enter the email address the proxy is connected to:");
    let mut connected_address = String::new();
    io::stdin().read_line(&mut connected_address).expect("");
    let connected_address = connected_address.replace("\n", "");

    println!("Please enter your full signing keypair");
    let mut signing_keypair_string = String::new();
    io::stdin().read_line(&mut signing_keypair_string).expect("");
    let signing_keypair_string = signing_keypair_string.replace("\n", "");
    let signing_keypair = construct_signing_keypair(signing_keypair_string);

    let mut re_enc_target: Option<Target> = None;

    loop {
        let mut imap_session = connect(imap_address.clone(), imap_port, imap_username.clone(), imap_password.clone());

        let messages = load_unseen_messages(imap_session);

        for message in messages {
            if message.subject == "COMMAND" {
                let command = parse(message.text);
                match command {
                    Command::Start { target } => {
                        re_enc_target = Some(target);
                    }
                    Command::Stop => {}
                }
                continue;
            }
            let mut smtp_connection = smtp_connect(smtp_address.clone(), smtp_port, smtp_username.clone(), smtp_password.clone());

            let re_encrypted_message = re_encrypt(
                re_enc_target.clone().unwrap(),
                message.clone(),
                signing_keypair.clone(),
            );

            send_message(re_enc_target.clone().unwrap(), re_encrypted_message, connected_address.clone(), smtp_connection);
        }
        println!("Going to Sleep");
        let sleep_time = time::Duration::from_secs(30);

        thread::sleep(sleep_time);
        println!("Wake up");
    }
}

#[cfg(test)]
mod tests {
    use crate::message::message::build_message;
    use crate::message_loader::message_loader::load_unseen_messages;
    use crate::message_transmitter::message_transmitter::send_message;
    use crate::re_encryption::re_encryption::{
        construct_plaintext, convert_to_string, convert_to_vec_u8, create_enc_value,
        create_encrypted_once_value_string, deconstruct_plaintext, re_encrypt,
    };
    use crate::target::target::build_target;
    use imap::Session;
    use lettre::{SmtpClient, SmtpTransport, Transport};
    use lettre_email::EmailBuilder;
    use native_tls::TlsStream;
    use recrypt::api::*;
    use recrypt::api::{EncryptedMessage, EncryptedValue};
    use std::borrow::Borrow;
    use std::convert::TryInto;
    use std::net::TcpStream;
    use std::ops::Deref;

    fn tls() -> native_tls::TlsConnector {
        native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap()
    }

    fn generate_imap_session(user: &str) -> Session<TlsStream<TcpStream>> {
        let host = std::env::var("TEST_HOST").unwrap_or("127.0.0.1".to_string());
        let client = imap::ClientBuilder::new(&host, 3993)
            .connect(|domain, tcp| {
                let ssl_conn = tls();
                Ok(native_tls::TlsConnector::connect(&ssl_conn, domain, tcp).unwrap())
            })
            .unwrap();
        //let mut client = imap::connect((host.as_str(), 3993), host.as_str(), &tls).unwrap();
        let mut imap_session = client.login(user, user).unwrap();
        //imap_session.debug = true;

        return imap_session;
    }

    fn generate_smtp_session(user: &str) -> SmtpTransport {
        let host = std::env::var("TEST_HOST").unwrap_or("127.0.0.1".to_string());
        let creds =
            lettre::smtp::authentication::Credentials::new(user.to_string(), user.to_string());
        let mut smtp_transport = SmtpClient::new(
            &format!("{}:3465", host.as_str()),
            lettre::ClientSecurity::Wrapper(lettre::ClientTlsParameters {
                connector: tls(),
                domain: "smpt.example.com".to_string(),
            }),
        )
        .unwrap()
        .credentials(creds)
        .transport();

        return smtp_transport;
    }

    fn send_test_message(user: &str, to: String, from: String, subject: String, text: String) {
        let email_builder = EmailBuilder::new()
            .to(to)
            .from(from)
            .subject(subject)
            .text(text);

        let email = email_builder.build().unwrap().into();

        let mut mailer = generate_smtp_session(user);

        let result = mailer.send(email);
    }

    #[test]
    #[ignore]
    fn one_email_full_random_plaintext() {
        //Test preparation
        let origin = "origin@localhost";
        let alice = "alice@localhost";
        let credentials_alice =
            lettre::smtp::authentication::Credentials::new(alice.to_string(), alice.to_string());
        let bob = "bob@localhost";

        // create a new recrypt
        let mut recrypt = Recrypt::new();

        // generate a plaintext to encrypt
        let plaintext_origin = recrypt.gen_plaintext();

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
        let encrypted_val_origin = recrypt
            .encrypt(&plaintext_origin, &alice_pub_key, &origin_signing_keypair)
            .unwrap();

        println!("\nOrigin:");
        let encrypted_val_origin_string = create_encrypted_once_value_string(encrypted_val_origin);
        println!("Send: {}", encrypted_val_origin_string);
        send_test_message(
            origin,
            alice.to_string(),
            origin.to_string(),
            "Testnachricht".to_string(),
            encrypted_val_origin_string.clone(),
        );

        //Test core
        println!("\nTransform:");
        let target = build_target(bob.to_string(), alice_to_bob_transform_key);

        let message = load_unseen_messages(generate_imap_session(alice))
            .pop()
            .unwrap();

        println!("Received: {}", message.text);
        assert_eq!(encrypted_val_origin_string, message.text);

        let re_encrypted_message = re_encrypt(
            target.clone(),
            message.clone(),
            alice_signing_keypair.clone(),
        );
        println!("Send: {}", re_encrypted_message.text);
        send_test_message(
            alice,
            target.address.clone(),
            alice.to_string(),
            re_encrypted_message.subject.to_string(),
            re_encrypted_message.text.to_string(),
        );

        //Test evaluation
        println!("\nBob:");
        let mut message_bob = load_unseen_messages(generate_imap_session(bob))
            .pop()
            .unwrap();

        assert_eq!(re_encrypted_message.text, message_bob.text);
        let enc_bob_value = create_enc_value(message_bob.text);

        let plaintext_bob = recrypt.decrypt(enc_bob_value, &bob_priv_key).unwrap();

        println!("Original: {:?}", plaintext_origin);
        println!("Bob: {:?}", plaintext_bob);
        assert_eq!(plaintext_origin, plaintext_bob);
    }

    #[test]
    #[ignore]
    fn one_email_full() {
        //Test preparation
        let origin = "origin@localhost";
        let alice = "alice@localhost";
        let credentials_alice =
            lettre::smtp::authentication::Credentials::new(alice.to_string(), alice.to_string());
        let bob = "bob@localhost";

        // create a new recrypt
        let mut recrypt = Recrypt::new();

        // generate a plaintext to encrypt
        let plaintext_origin =
            construct_plaintext("Hallo dies ist eine Testnachricht\nzum testen.".to_string());

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
        let encrypted_val_origin = recrypt
            .encrypt(&plaintext_origin, &alice_pub_key, &origin_signing_keypair)
            .unwrap();

        println!("\nOrigin:");
        let encrypted_val_origin_string = create_encrypted_once_value_string(encrypted_val_origin);
        println!("Send: {}", encrypted_val_origin_string);
        send_test_message(
            origin,
            alice.to_string(),
            origin.to_string(),
            "Testnachricht".to_string(),
            encrypted_val_origin_string.clone(),
        );

        //Test core
        println!("\nTransform:");
        let target = build_target(bob.to_string(), alice_to_bob_transform_key);

        let message = load_unseen_messages(generate_imap_session(alice))
            .pop()
            .unwrap();

        println!("Received: {}", message.text);
        assert_eq!(encrypted_val_origin_string, message.text);

        let re_encrypted_message = re_encrypt(
            target.clone(),
            message.clone(),
            alice_signing_keypair.clone(),
        );
        println!("Send: {}", re_encrypted_message.text);
        send_test_message(
            alice,
            target.address.clone(),
            alice.to_string(),
            re_encrypted_message.subject.to_string(),
            re_encrypted_message.text.to_string(),
        );

        //Test evaluation
        println!("\nBob:");
        let mut messages_bob = load_unseen_messages(generate_imap_session(bob))
            .pop()
            .unwrap();

        println!("\nreceived Bob: {}", messages_bob.text);
        assert_eq!(re_encrypted_message.text, messages_bob.text);
        let enc_bob_value = create_enc_value(messages_bob.text);

        let plaintext_bob = recrypt.decrypt(enc_bob_value, &bob_priv_key).unwrap();

        println!(
            "Original: {}",
            deconstruct_plaintext(plaintext_origin.clone())
        );
        println!("Bob: {}", deconstruct_plaintext(plaintext_bob.clone()));
        assert_eq!(plaintext_origin, plaintext_bob);
    }
}
