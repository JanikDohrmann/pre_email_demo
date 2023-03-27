extern crate imap;

use crate::message_loader::{connect, load_unseen_messages};
use crate::message_transmitter::{send_message, smtp_connect};
use crate::target::Target;

use crate::command::{parse, Command};
use crate::re_encryption::{construct_signing_keypair, re_encrypt, deconstruct_transform_key};
use std::io;
use std::{thread, time};

mod command;
mod message;
mod message_loader;
mod message_transmitter;
mod re_encryption;
mod target;

#[macro_use]
extern crate pest_derive;

use serde::{Deserialize, Serialize};
use std::fs::read_to_string;

/// Struct for loading the config file.
#[derive(Serialize, Deserialize)]
struct Config {
    smtp_address: String,
    smtp_port: u16,
    imap_address: String,
    imap_port: u16
}

/// The default sleep time of the proxy in seconds.
const DEFAULT_SLEEP_TIME: u64 = 30;

/// Main funktion of the proxy. Contains the main loop of the system.
fn main() {
    // First the config file will be loaded.
    let config_string = read_to_string("config.json").unwrap();
    let config:Config = serde_json::from_str(config_string.as_str()).unwrap();

    let smtp_address = config.smtp_address;
    let smtp_port = config.smtp_port;
    let imap_address = config.imap_address;
    let imap_port = config.imap_port;

    //Now the proxy will be configured
    println!("Willkommen im Proxy Re-Encryption Demonstrator!");
    println!("\n\nBevor Nachrichten weitergeleitet werden können muss der Proxy konfiguriert werden.\nWir beginnen mit der Verbindung zum IMAP-Server.");
    let imap_username;
    loop {
        println!("Bitte gebe den Nutzernamen für den IMAP-Server ein:");
        let mut imap_username_loop = String::new();
        io::stdin().read_line(&mut imap_username_loop).expect("");
        let imap_username_loop = imap_username_loop.replace("\n", "").replace("\r", "");
        if !imap_username_loop.is_empty() {
            imap_username = imap_username_loop;
            break;
        }
    }

    let imap_password;
    loop {
        println!("Bitte gebe das Passwort für den IMAP-Server ein:");
        let mut imap_password_loop = String::new();
        io::stdin().read_line(&mut imap_password_loop).expect("");
        let imap_password_loop = imap_password_loop.replace("\n", "").replace("\r", "");
        if !imap_password_loop.is_empty() {
            imap_password = imap_password_loop;
            break;
        }
    }

    let smtp_username;
    loop {
        println!("Bitte gebe den Nutzernamen für den SMTP-Server ein:");
        let mut smtp_username_loop = String::new();
        io::stdin().read_line(&mut smtp_username_loop).expect("");
        let smtp_username_loop = smtp_username_loop.replace("\n", "").replace("\r", "");
        if !smtp_username_loop.is_empty() {
            smtp_username = smtp_username_loop;
            break;
        }
    }

    let smtp_password;
    loop {
        println!("Bitte gebe das Passwort für den SMTP-Server ein:");
        let mut smtp_password_loop = String::new();
        io::stdin().read_line(&mut smtp_password_loop).expect("");
        let smtp_password_loop = smtp_password_loop.replace("\n", "").replace("\r", "");
        if !smtp_password_loop.is_empty() {
            smtp_password = smtp_password_loop;
            break;
        }
    }

    println!("Im letzten Schritt wird die Umschlüsselung konfiguriert");
    let connected_address;
    loop {
        println!("Bitte gebe deine E-Mail-Adresse ein:");
        let mut connected_address_loop = String::new();
        io::stdin().read_line(&mut connected_address_loop).expect("");
        let connected_address_loop = connected_address_loop.replace("\n", "").replace("\r", "");
        if !connected_address_loop.is_empty() {
            connected_address = connected_address_loop;
            break;
        }
    }

    let signing_keypair;
    loop {
        println!("Bitte gebe das vollständige Signaturschlüsselpaar ein:");
        let mut signing_keypair_string = String::new();
        io::stdin()
            .read_line(&mut signing_keypair_string)
            .expect("");
        let signing_keypair_string = signing_keypair_string.replace("\n", "").replace("\r", "");
        let signing_keypair_option = construct_signing_keypair(signing_keypair_string);
        if signing_keypair_option.is_some() {
            signing_keypair = signing_keypair_option.unwrap();
            break;
        }
    }

    let mut re_enc_target: Option<Target> = None;

    loop {
        let imap_session = connect(
            imap_address.clone(),
            imap_port,
            imap_username.clone(),
            imap_password.clone(),
        );

        println!("\nDer Server lädt alle ungesehenen Nachrichten vom IMAP-Server.");

        let messages = load_unseen_messages(imap_session);

        println!(
            "\nEs wurden {} ungesehene Nachrichten gefunden.",
            messages.len()
        );
        println!("\nDer Proxy wird alle Nachrichten durchlaufen.\nDabei wird für jede E-Mail geprüft, ob es sich bei diesen um einen Befehl handelt.\nWenn dies der Fall ist wird der Befehl verarbeitet.\nWenn es sich nicht um einen Befehl handelt, wird die E-Mail bei eingeschalteter Weiterleitung umgeschlüsselt und an den neuen Empfänger gesendet.");
        for message in messages {
            println!("Prüfen, ob die E-Mail ein Befehl ist.");
            if message.from == connected_address && message.subject == "COMMAND" {
                println!("Die E-Mail ist ein Befehl. Sie wird jetzt geparsed.");
                let command = parse(message.text);
                match command {
                    Command::Start { target } => {
                        re_enc_target = Some(target);
                        println!("Es handelt sich um einen Startbefehl.\nZieladresse:{}\nRe-Encryption-Schlüssel: {}\nDie Weiterleitung wird gestartet.",re_enc_target.clone().unwrap().address, deconstruct_transform_key(re_enc_target.clone().unwrap().re_key));
                    }
                    Command::Stop => {
                        println!(
                            "Es handelt sich um einen Stoppbefehl. Die Weiterleitung wird gestoppt."
                        );
                        re_enc_target = None;
                    }
                }
                continue;
            }
            println!("\nBevor die E-Mail Umgeschlüsselt und Weitergeleitet wird, wird geprüft ob die Weiterleitung aktiv ist.");
            if re_enc_target.is_some() {
                let smtp_connection = smtp_connect(
                    smtp_address.clone(),
                    smtp_port,
                    smtp_username.clone(),
                    smtp_password.clone(),
                );

                println!("\nDie E-Mail mit dem Betreff {} wird mit dem Re-Encryption-Schlüssel umgeschlüsselt.", message.clone().subject);
                let re_encrypted_message = re_encrypt(
                    re_enc_target.clone().unwrap(),
                    message.clone(),
                    signing_keypair.clone(),
                );
                println!("\nNach der Umschlüsselung wird die Nachricht an die Zieladresse {} gesendet.", re_enc_target.clone().unwrap().address);
                send_message(
                    re_enc_target.clone().unwrap(),
                    re_encrypted_message,
                    connected_address.clone(),
                    smtp_connection,
                );
            }
        }

        let sleep_time = DEFAULT_SLEEP_TIME;
        println!("Der Proxy wartet für {} Sekunden\n----------\n", sleep_time);
        thread::sleep(time::Duration::from_secs(sleep_time));
    }
}

#[cfg(test)]
mod tests {
    use crate::message_loader::{connect, load_unseen_messages};
    use crate::message_transmitter::{send_message, smtp_connect};
    use crate::re_encryption::{
        construct_plaintext, construct_enc_value,
        re_encrypt, deconstruct_encrypted_value
    };
    use crate::target::build_target;
    use lettre::Transport;
    use lettre_email::EmailBuilder;
    use recrypt::api::*;

    /// Helper method for sending test messages.
    fn send_test_message(user: &str, to: String, from: String, subject: String, text: String) {
        let email_builder = EmailBuilder::new()
            .to(to)
            .from(from)
            .subject(subject)
            .text(text);

        let email = email_builder.build().unwrap().into();

        let mut mailer = smtp_connect(
            "127.0.0.1".to_string(),
            3465,
            user.to_string(),
            user.to_string(),
        );

        let _result = mailer.send(email);
    }

    ///Test for a full re-encryption cycle with a random plaintext.
    /// Needs Greenmail or other Mailserver to work.
    #[test]
    #[ignore]
    fn one_email_full_random_plaintext() {
        //Test preparation
        let origin = "origin@localhost";
        let alice = "alice@localhost";
        let bob = "bob@localhost";

        let recrypt = Recrypt::new();

        let plaintext_origin = recrypt.gen_plaintext();

        let origin_signing_keypair = recrypt.generate_ed25519_key_pair();
        let alice_signing_keypair = recrypt.generate_ed25519_key_pair();

        let (alice_priv_key, alice_pub_key) = recrypt.generate_key_pair().unwrap();
        let (bob_priv_key, bob_pub_key) = recrypt.generate_key_pair().unwrap();

        let alice_to_bob_transform_key = recrypt
            .generate_transform_key(&alice_priv_key, &bob_pub_key, &alice_signing_keypair)
            .unwrap();

        let encrypted_val_origin = recrypt
            .encrypt(&plaintext_origin, &alice_pub_key, &origin_signing_keypair)
            .unwrap();

        let encrypted_val_origin_string = deconstruct_encrypted_value(encrypted_val_origin);
        send_test_message(
            origin,
            alice.to_string(),
            origin.to_string(),
            "Testnachricht".to_string(),
            encrypted_val_origin_string.clone(),
        );

        //Test core
        let target = build_target(bob.to_string(), alice_to_bob_transform_key);

        let message = load_unseen_messages(connect(
            "127.0.0.1".to_string(),
            3993,
            alice.to_string(),
            alice.to_string(),
        ))
        .pop()
        .unwrap();

        assert_eq!(encrypted_val_origin_string, message.text);

        let re_encrypted_message = re_encrypt(
            target.clone(),
            message.clone(),
            alice_signing_keypair.clone(),
        );

        send_message(
            target,
            re_encrypted_message.clone(),
            alice.to_string(),
            smtp_connect(
                "127.0.0.1".to_string(),
                3465,
                alice.to_string(),
                alice.to_string(),
            ),
        );

        //Test evaluation
        let message_bob = load_unseen_messages(connect(
            "127.0.0.1".to_string(),
            3993,
            bob.to_string(),
            bob.to_string(),
        ))
        .pop()
        .unwrap();

        assert_eq!(re_encrypted_message.text, message_bob.text);
        let enc_bob_value = construct_enc_value(message_bob.text);

        let plaintext_bob = recrypt.decrypt(enc_bob_value, &bob_priv_key).unwrap();

        assert_eq!(plaintext_origin, plaintext_bob);
    }

    ///Test for a full re-encryption cycle with "Hallo dies ist eine Testnachricht\nzum testen."
    /// as a plaintext.
    /// Needs Greenmail or other Mailserver to work.
    #[test]
    #[ignore]
    fn one_email_full() {
        //Test preparation
        let origin = "origin@localhost";
        let alice = "alice@localhost";
        let bob = "bob@localhost";

        let recrypt = Recrypt::new();

        let plaintext_origin =
            construct_plaintext("Hallo dies ist eine Testnachricht\nzum testen.".to_string());

        let origin_signing_keypair = recrypt.generate_ed25519_key_pair();
        let alice_signing_keypair = recrypt.generate_ed25519_key_pair();

        let (alice_priv_key, alice_pub_key) = recrypt.generate_key_pair().unwrap();
        let (bob_priv_key, bob_pub_key) = recrypt.generate_key_pair().unwrap();

        let alice_to_bob_transform_key = recrypt
            .generate_transform_key(&alice_priv_key, &bob_pub_key, &alice_signing_keypair)
            .unwrap();

        let encrypted_val_origin = recrypt
            .encrypt(&plaintext_origin, &alice_pub_key, &origin_signing_keypair)
            .unwrap();

        let encrypted_val_origin_string = deconstruct_encrypted_value(encrypted_val_origin);
        send_test_message(
            origin,
            alice.to_string(),
            origin.to_string(),
            "Testnachricht".to_string(),
            encrypted_val_origin_string.clone(),
        );

        //Test core
        let target = build_target(bob.to_string(), alice_to_bob_transform_key);

        let message = load_unseen_messages(connect(
            "127.0.0.1".to_string(),
            3993,
            alice.to_string(),
            alice.to_string(),
        ))
        .pop()
        .unwrap();

        assert_eq!(encrypted_val_origin_string, message.text);

        let re_encrypted_message = re_encrypt(
            target.clone(),
            message.clone(),
            alice_signing_keypair.clone(),
        );

        send_message(
            target,
            re_encrypted_message.clone(),
            alice.to_string(),
            smtp_connect(
                "127.0.0.1".to_string(),
                3465,
                alice.to_string(),
                alice.to_string(),
            ),
        );

        //Test evaluation
        let messages_bob = load_unseen_messages(connect(
            "127.0.0.1".to_string(),
            3993,
            bob.to_string(),
            bob.to_string(),
        ))
        .pop()
        .unwrap();

        assert_eq!(re_encrypted_message.text, messages_bob.text);
        let enc_bob_value = construct_enc_value(messages_bob.text);

        let plaintext_bob = recrypt.decrypt(enc_bob_value, &bob_priv_key).unwrap();

        assert_eq!(plaintext_origin, plaintext_bob);
    }
}
