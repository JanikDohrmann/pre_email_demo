pub mod message_loader {
    use crate::message::message::{Message, build_message};
    use self::imap::Session;
    use native_tls::TlsStream;
    use std::net::TcpStream;

    extern crate imap;

    use std::ops::Deref;
    use std::borrow::{Borrow, BorrowMut};

    pub fn load_unseen_messages(mut session: Session<TlsStream<TcpStream>>) -> Vec<Message>{
        session.select("INBOX").unwrap();
        let inbox = session.search("UNSEEN").unwrap();
        let i = inbox.iter().next().unwrap();

        let mut messages: Vec<Message> = Vec::new();

        for element in inbox.iter() {
            let message = load_message(&mut session, *element).unwrap().unwrap();
            messages.push(message);
        }

        return messages;
    }

    pub fn load_message(mut session: &mut Session<TlsStream<TcpStream>>, message_number: u32) -> imap::error::Result<Option<Message>>{
        // fetch message number 1 in this mailbox, along with its RFC822 field.
        // RFC 822 dictates the format of the body of e-mails
        let messages = session.fetch(message_number.to_string(),"(BODY[TEXT] BODY[HEADER] ENVELOPE)")?;

        let message = if let Some(m) = messages.iter().next() {
            m

        } else {
            return Ok(None);
        };
/*
        println!("Message: {}", message.message);
        println!("Envelope: {}", message.envelope().is_some());
        println!("Body: {}", message.body().is_some());
        println!("Text: {}", message.text().is_some());
        println!("Header: {}", message.header().is_some());

        println!("\n*****\n");*/
        let envelope = message.envelope().unwrap();


        let subject = std::str::from_utf8(envelope.subject.as_ref().unwrap().deref())
            .expect("message was not valid utf-8")
            .to_string();

        let mailbox = envelope.from.as_ref().unwrap().first().unwrap().mailbox.as_ref().unwrap().deref();
        //let mailbox = envelope.from.as_ref().unwrap().first().unwrap().mailbox.unwrap();
        let mailbox = std::str::from_utf8(mailbox)
            .expect("message was not valid utf-8")
            .to_string();
        let host = envelope.from.as_ref().unwrap().first().unwrap().host.as_ref().unwrap().deref();
        let host=  std::str::from_utf8(host)
            .expect("message was not valid utf-8")
            .to_string();
        let from = format!("{}@{}", mailbox, host);


        let message_text = std::str::from_utf8(message.text().unwrap())
            .expect("message was not valid utf-8")
            .to_string();

        let message = build_message(subject, from, message_text);

        Ok(Some(message))
    }

    /// Creates an authorized session that is connected to an IMAP server.
    /// domain: The address of the IMAP server.
    /// username: The username on that server for the login.
    /// password: the password on that server for the login.
    pub fn connect(domain: String, username: String, password: String) -> Session<TlsStream<TcpStream>> {
        let tls = native_tls::TlsConnector::builder().build().unwrap();

        let client =imap::ClientBuilder::new(domain.as_str(), 993).native_tls().unwrap();
        let imap_session = client
            .login(username, password)
            .map_err(|e| e.0).ok().unwrap();

        return imap_session;
    }
}