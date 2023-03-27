mod encryption;
mod message;
mod message_loader;
mod message_transmitter;
mod target;

use crate::encryption::{deconstruct_signing_keypair, construct_plaintext, deconstruct_encrypted_value, convert_to_string, deconstruct_public_key, deconstruct_private_key, deconstruct_transform_key, construct_signing_keypair, construct_private_key, convert_to_vec_u8, construct_public_key, construct_enc_value, deconstruct_plaintext};
use crate::message_loader::{connect, load_unseen_messages};
use crate::message_transmitter::{send_message, smtp_connect};
use recrypt::prelude::*;
use std::io;
use crate::message::build_message;

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

/// Main method of the client.
fn main() {
    // First the config file will be loaded.
    let config_string = read_to_string("config.json").unwrap();
    let config:Config = serde_json::from_str(config_string.as_str()).unwrap();

    let smtp_address = config.smtp_address;
    let smtp_port = config.smtp_port;
    let imap_address = config.imap_address;
    let imap_port = config.imap_port;

    // In the main loop the client has several options the user can choose from.
    let recrypt = Recrypt::new();
    println!("Willkommen im PRE-Demo-Client!");
    loop {
        // The user can type a number for choosing an option.
        println!("\n\nBitte gebe eine Nummer ein:");
        println!("1 - E-Mail senden");
        println!("2 - Ungesehene E-Mails laden");
        println!("3 - Signaturschlüsselpaar generieren");
        println!("4 - WC09 Schlüsselpaar generieren");
        println!("5 - Startbefehl senden");
        println!("6 - Stoppbefehl senden");
        let mut option = String::new();
        io::stdin().read_line(&mut option).expect("");
        let option = option.replace("\n", "").replace("\r", "");

        match option.as_str() {
            "1" => { //Option for sending encrypted e-mails.
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

                let public_key;
                loop {
                    println!("Bitte gebe den öffentlichen Schlüssel des Empfängers ein:");
                    let mut public_key_string = String::new();
                    io::stdin()
                        .read_line(&mut public_key_string)
                        .expect("");
                    let public_key_string = public_key_string.replace("\n", "").replace("\r", "");
                    let public_key_option = construct_public_key(&*convert_to_vec_u8(public_key_string));
                    if public_key_option.is_some() {
                        public_key = public_key_option.unwrap();
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

                let subject;
                loop {
                    println!("Bitte gebe den Betreff der E-Mail ein:");
                    let mut subject_loop = String::new();
                    io::stdin().read_line(&mut subject_loop).expect("");
                    let subject_loop = subject_loop.replace("\n", "").replace("\r", "");
                    if !subject_loop.is_empty() {
                        subject = subject_loop;
                        break;
                    }
                }

                let to;
                loop {
                    println!("Bitte gebe die Zieladresse der E-Mail ein:");
                    let mut to_loop = String::new();
                    io::stdin().read_line(&mut to_loop).expect("");
                    let to_loop = to_loop.replace("\n", "").replace("\r", "");
                    if !to_loop.is_empty() {
                        to = to_loop;
                        break;
                    }
                }

                let text;
                loop {
                    println!("Bitte gebe den Text der E-Mail ein:");
                    let mut text_loop = String::new();
                    io::stdin().read_line(&mut text_loop).expect("");
                    let text_loop = text_loop.replace("\n", "").replace("\r", "");
                    if !text_loop.is_empty() {
                        text = text_loop;
                        break;
                    }
                }

                let plaintext = construct_plaintext(text);
                let encrypted_text = recrypt.encrypt(&plaintext, &public_key, &signing_keypair).unwrap();

                let smtp_connection = smtp_connect(
                    smtp_address.clone(),
                    smtp_port,
                    smtp_username.clone(),
                    smtp_password.clone(),
                );

                let message = build_message(subject, connected_address, deconstruct_encrypted_value(encrypted_text));

                send_message(message, to, smtp_connection);

            }
            "2" => { //Option for checking for unseen e-mails form an IMAP server.
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

                let private_key;
                loop {
                    println!("Bitte gebe deinen privaten Schlüssel ein:");
                    let mut private_key_string = String::new();
                    io::stdin()
                        .read_line(&mut private_key_string)
                        .expect("");
                    let private_key_string = private_key_string.replace("\n", "").replace("\r", "");
                    let private_key_option = construct_private_key(&*convert_to_vec_u8(private_key_string));
                    if private_key_option.is_some() {
                        private_key = private_key_option.unwrap();
                        break;
                    }
                }

                let imap_session = connect(
                    imap_address.clone(),
                    imap_port,
                    imap_username.clone(),
                    imap_password.clone(),
                );

                let messages = load_unseen_messages(imap_session);

                println!("Ungesehene Nachrichten: {}", messages.len());
                println!("\n--------\n");

                for message in messages {
                    let encrypted_text = construct_enc_value(message.text);
                    let decrypted_text = recrypt.decrypt(encrypted_text, &private_key).unwrap();
                    println!("--------\n");
                    println!("Betreff: {}", message.subject);
                    println!("Absender: {}", message.from);
                    println!("\n--------\n");
                    println!("{}", deconstruct_plaintext(decrypted_text));
                    println!("\n--------\n\n");
                }

            }
            "3" => { //Option for generating an ed25519 signing keypair.
                let signing_keypair = recrypt.generate_ed25519_key_pair();
                println!("Signaturschlüsselpaar: {}", deconstruct_signing_keypair(signing_keypair));
            }
            "4" => { //Option for generating a keypair for the encryption.
                let keypair = recrypt.generate_key_pair().unwrap();
                println!("Privater Schlüssel: {}", convert_to_string(deconstruct_private_key(keypair.0)));
                println!("Öffentlicher Schlüssel: {}", convert_to_string(deconstruct_public_key(keypair.1)));
            }
            "5" => { //Option for sending a start command. The re-encryption key will be generated in this client.
                let private_key;
                loop {
                    println!("Bitte gebe deinen privaten Schlüssel ein:");
                    let mut private_key_string = String::new();
                    io::stdin()
                        .read_line(&mut private_key_string)
                        .expect("");
                    let private_key_string = private_key_string.replace("\n", "").replace("\r", "");
                    let private_key_option = construct_private_key(&*convert_to_vec_u8(private_key_string));
                    if private_key_option.is_some() {
                        private_key = private_key_option.unwrap();
                        break;
                    }
                }


                let public_key;
                loop {
                    println!("Bitte gebe den öffentlichen Schlüssel des Empfängers ein:");
                    let mut public_key_string = String::new();
                    io::stdin()
                        .read_line(&mut public_key_string)
                        .expect("");
                    let public_key_string = public_key_string.replace("\n", "").replace("\r", "");
                    let public_key_option = construct_public_key(&*convert_to_vec_u8(public_key_string));
                    if public_key_option.is_some() {
                        public_key = public_key_option.unwrap();
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

                let transform_key = recrypt.generate_transform_key(&private_key, &public_key, &signing_keypair).unwrap();

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

                let target_address;
                loop {
                    println!("Bitte gebe die Zieladresse der Weiterleitung ein:");
                    let mut target_address_loop = String::new();
                    io::stdin().read_line(&mut target_address_loop).expect("");
                    let target_address_loop = target_address_loop.replace("\n", "").replace("\r", "");
                    if !target_address_loop.is_empty() {
                        target_address = target_address_loop;
                        break;
                    }
                }

                let smtp_connection = smtp_connect(
                    smtp_address.clone(),
                    smtp_port,
                    smtp_username.clone(),
                    smtp_password.clone(),
                );

                println!("Der Re-Encryption-Schlüssel wurde mithilfe des privaten Schlüssels des Delegators\nund dem öffentlichen Schlüssels des Delegatees lokal berechnet\nund wird jetzt zusammen mit der Zieladresse über den Startbefehl versendet.");

                let text = format!("START\nTA:{}\nRK:{}", target_address, deconstruct_transform_key(transform_key));
                let message = build_message("COMMAND".to_string(), connected_address.clone(), text);

                send_message(message, connected_address, smtp_connection);
            }
            "6" => { //Option for sending a stop command.
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

                let smtp_connection = smtp_connect(
                    smtp_address.clone(),
                    smtp_port,
                    smtp_username.clone(),
                    smtp_password.clone(),
                );

                let message = build_message("COMMAND".to_string(), connected_address.clone(), "STOP".to_string());

                send_message(message, connected_address, smtp_connection);
            }
            _ => {
                continue
            },
        }
    }
}
