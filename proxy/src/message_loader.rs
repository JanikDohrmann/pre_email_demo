use self::imap::Session;
use crate::message::{build_message, Message};
use native_tls::TlsStream;
use std::net::TcpStream;

extern crate imap;

use std::ops::Deref;

/// Retrieves all unseen messages from an IMAP server
/// /// # Arguments
/// * `session` - The session that is used for the queries.
/// # Return
/// Returns a Vector with all unseen Messages.
pub fn load_unseen_messages(mut session: Session<TlsStream<TcpStream>>) -> Vec<Message> {
    session.select("INBOX").unwrap();
    let inbox = session.search("UNSEEN").unwrap();

    let mut messages: Vec<Message> = Vec::new();

    for element in inbox.iter() {
        let message = load_message(&mut session, *element).unwrap().unwrap();
        messages.push(message);
    }

    return messages;
}

/// Retrieves a specific message from an IMAP server
/// /// # Arguments
/// * `session` - The session that is used for the queries.
/// * `message_number` - The number of the message that should be retrieved.
/// # Return
/// Returns the specified message, if it exist.
fn load_message(
    session: &mut Session<TlsStream<TcpStream>>,
    message_number: u32,
) -> imap::error::Result<Option<Message>> {
    let messages = session.fetch(
        message_number.to_string(),
        "(BODY[TEXT] BODY[HEADER] ENVELOPE)",
    )?;

    let message = if let Some(m) = messages.iter().next() {
        m
    } else {
        return Ok(None);
    };
    let envelope = message.envelope().unwrap();

    let subject = std::str::from_utf8(envelope.subject.as_ref().unwrap().deref())
        .expect("message was not valid utf-8")
        .to_string();

    let mailbox = envelope
        .from
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .mailbox
        .as_ref()
        .unwrap()
        .deref();
    let mailbox = std::str::from_utf8(mailbox)
        .expect("message was not valid utf-8")
        .to_string();
    let host = envelope
        .from
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .host
        .as_ref()
        .unwrap()
        .deref();
    let host = std::str::from_utf8(host)
        .expect("message was not valid utf-8")
        .to_string();
    let from = format!("{}@{}", mailbox, host);

    let message_text_vec = std::str::from_utf8(message.text().unwrap())
        .expect("message was not valid utf-8")
        .to_string();

    let message_text_vec = message_text_vec.split("\r\n").collect::<Vec<_>>();

    let message = build_message(subject, from, message_text_vec[4].to_string());

    Ok(Some(message))
}

/// Creates an authorized session that is connected to an IMAP server.
/// domain: The address of the IMAP server.
/// username: The username on that server for the login.
/// password: the password on that server for the login.
pub fn connect(
    domain: String,
    port: u16,
    username: String,
    password: String,
) -> Session<TlsStream<TcpStream>> {
    let client = imap::ClientBuilder::new(domain.as_str(), port)
        .connect(|domain, tcp| {
            let ssl_conn = tls();
            Ok(native_tls::TlsConnector::connect(&ssl_conn, domain, tcp).unwrap())
        })
        .unwrap();
    let imap_session = client
        .login(username, password)
        .map_err(|e| e.0)
        .ok()
        .unwrap();

    return imap_session;
}

///Method for generating a TlsConnector.
/// The tls connection will accept invalid certificates because of the use of greenmail for the demonstration.
fn tls() -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}
