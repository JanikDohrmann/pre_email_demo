extern crate imap;

use crate::message_loader::message_loader::{parse_message, load_message};
use crate::message_transmitter::message_transmitter::send_message;
use crate::target::target::build_target;
use recrypt::api::TransformKey;

use recrypt::prelude::*;
use crate::message::message::build_message;
use lettre::{SmtpClient, EmailAddress, Envelope, SendableEmail, Transport};
use chrono::Utc;
use native_tls::TlsConnector;
use std::net::TcpStream;

mod message;
mod message_loader;
mod target;
mod command;
mod message_transmitter;
mod re_encryption;

#[macro_use]
extern crate pest_derive;

fn main() {
    let user = "janik@localhost";

    let tls = native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).danger_accept_invalid_hostnames(true).build().unwrap();
    
    let host = std::env::var("TEST_HOST").unwrap_or("127.0.0.1".to_string());
    let mut client = imap::connect((host.as_str(), 3993), host.as_str(), &tls).unwrap();
    client.debug = true;

    /*let mut client = imap::connect_starttls((host.as_str(), 3993), host.as_str(), &tls).unwrap();
    client.debug = true;*/

    let mut imap_session = client
        .login(user, user)
        .map_err(|e| e.0).unwrap();



    let creds = lettre::smtp::authentication::Credentials::new(user.to_string(), user.to_string());
    let mut smtp_transport = SmtpClient::new(
        &format!(
            "{}:3465",
            host.as_str()
        ),
        lettre::ClientSecurity::Wrapper(lettre::ClientTlsParameters {
            connector: tls,
            domain: host,
        }),
    )
        .unwrap()
        .credentials(creds)
        .transport();

    let target_address = EmailAddress::new(user.to_string()).unwrap();
    let origin_address = EmailAddress::new("inbox2@localhost".to_string()).unwrap();

    let mut target_address_vec = Vec::new();
    target_address_vec.push(target_address);

    let envelope = Envelope::new(Option::from(origin_address), target_address_vec).unwrap();

    //message-id nach RFC5322
    let left_side = format!("{}", Utc::now())
        .replace(" UTC", "")
        .replace("-", "")
        .replace(" ", "")
        .replace(":", "")
        .replace(".", "");

    let message_id = format!("<{}@pre_demo>", left_side);

    let mut message_text_vector = "Dies ist ein Test".as_bytes().to_vec();

    let email = SendableEmail::new(envelope, message_id, message_text_vector);

    let result = smtp_transport.send(email);

    if result.is_ok() {
        println!("Email sent");
    } else {
        println!("Could not send email: {:?}", result);
    }

    print!("{}", load_message(imap_session).unwrap().unwrap());

    /*
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
*/
}
