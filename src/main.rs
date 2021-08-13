extern crate imap;

use crate::message_loader::message_loader::{load_message, connect, load_unseen_messages};
use crate::message_transmitter::message_transmitter::send_message;
use crate::target::target::build_target;
use recrypt::api::TransformKey;

use recrypt::prelude::*;
use crate::message::message::build_message;
use lettre::{SmtpClient, EmailAddress, Envelope, SendableEmail, Transport};
use chrono::Utc;
use native_tls::TlsConnector;
use std::net::TcpStream;
use lettre_email::EmailBuilder;
use std::io;

mod message;
mod message_loader;
mod target;
mod command;
mod message_transmitter;
mod re_encryption;


fn main() {

}

fn pause() {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("");
}

#[cfg(test)]
mod tests {
    use recrypt::api::*;
    use imap::Session;
    use native_tls::TlsStream;
    use std::net::TcpStream;
    use lettre::{SmtpTransport, SmtpClient, Transport};
    use lettre_email::EmailBuilder;
    use crate::message_loader::message_loader::load_unseen_messages;
    use crate::re_encryption::re_encryption::{re_encrypt, convert_to_vec_u8, convert_to_string, create_enc_value, create_encrypted_once_value_string};
    use crate::message_transmitter::message_transmitter::send_message;
    use crate::target::target::build_target;
    use crate::message::message::build_message;
    use recrypt::api::{EncryptedMessage, EncryptedValue};
    use std::convert::TryInto;
    use std::ops::Deref;
    use std::borrow::Borrow;

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
        let mut imap_session = client
            .login(user, user)
            .unwrap();
        //imap_session.debug = true;

        return imap_session;
    }

    fn generate_smtp_session(user: &str) -> SmtpTransport {
        let host = std::env::var("TEST_HOST").unwrap_or("127.0.0.1".to_string());
        let creds = lettre::smtp::authentication::Credentials::new(user.to_string(), user.to_string());
        let mut smtp_transport = SmtpClient::new(
            &format!(
                "{}:3465",
                host.as_str()
            ),
            lettre::ClientSecurity::Wrapper(lettre::ClientTlsParameters {
                connector: tls(),
                domain: "smpt.example.com".to_string(),
            }),
        ).unwrap().credentials(creds).transport();

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
    fn one_email_full() {
        //Test preparation
        let origin = "origin@localhost";
        let alice = "alice@localhost";
        let credentials_alice = lettre::smtp::authentication::Credentials::new(alice.to_string(), alice.to_string());
        let bob = "bob@localhost";

        // create a new recrypt
        let mut recrypt = Recrypt::new();

        // generate a plaintext to encrypt
        let plaintext_origin = recrypt.gen_plaintext();

        // generate signing keys
        let origin_signing_keypair= recrypt.generate_ed25519_key_pair();
        let alice_signing_keypair= recrypt.generate_ed25519_key_pair();

        // generate a public/private keypair to encrypt the data to initially.
        let (alice_priv_key, alice_pub_key) = recrypt.generate_key_pair().unwrap();
        let (bob_priv_key, bob_pub_key) = recrypt.generate_key_pair().unwrap();

        // generate a transform key that will change which private key can decrypt the data
        let alice_to_bob_transform_key = recrypt.generate_transform_key(
            &alice_priv_key,
            &bob_pub_key,
            &alice_signing_keypair).unwrap();

        // encrypt the data to `initial_pub_key`!
        let encrypted_val_origin = recrypt.encrypt(&plaintext_origin, &alice_pub_key, &origin_signing_keypair).unwrap();

        println!("\nEnc Once String:");
        let encrypted_val_origin_string = create_encrypted_once_value_string(encrypted_val_origin);

        send_test_message(origin, alice.to_string(), origin.to_string(), "Testnachricht".to_string(), encrypted_val_origin_string.clone());

        //Test core
        println!("\nTransform:");
        let target = build_target(bob.to_string(), alice_to_bob_transform_key);

        let message1 = load_unseen_messages(generate_imap_session(alice)).pop().unwrap();
        let mut s = message1.text.split("\r\n").collect::<Vec<_>>();

        let message = build_message(message1.subject, message1.from, s[4].to_string());

        assert_eq!(encrypted_val_origin_string, message.text);

        let re_encrypted_message = re_encrypt(target.clone(), message.clone(), alice_signing_keypair.clone());
        println!("Send: {}", re_encrypted_message.text);
        send_test_message(alice, target.address.clone(), alice.to_string(), message.subject.to_string(), message.text.to_string());

        //Test evaluation
        let mut messages_bob = load_unseen_messages(generate_imap_session(bob)).pop().unwrap();
        println!("Received: {}", messages_bob.text);
        let mut b = messages_bob.text.split("\r\n").collect::<Vec<_>>();

        let bob_message1 = build_message(messages_bob.subject, messages_bob.from, b[4].to_string());

        println!("\nEnc Bob String:");
        println!("\nreceived Bob: {}", bob_message1.text);
        let enc_bob_value = create_enc_value(bob_message1.text);

        let plaintext_bob = recrypt.decrypt(enc_bob_value, &bob_priv_key).unwrap();

        assert_eq!(plaintext_origin, plaintext_bob)

    }
}
