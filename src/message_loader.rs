pub mod message_loader {
    use crate::message::message::{Message, build_message};
    use self::imap::Session;
    use native_tls::TlsStream;
    use std::net::TcpStream;

    extern crate imap;

    fn load_message() -> Message {
        build_message("Test".parse().unwrap(), "test".parse().unwrap(), "test".parse().unwrap())
    }

    /// Creates a authorized session that is connected to an IMAP server.
    /// domain: The address of the IMAP server.
    /// username: The username on that server for the login.
    /// password: the password on that server for the login.
    fn connect(domain: String, username: String, password: String) -> Option<Session<TlsStream<TcpStream>>> {
        let tls = native_tls::TlsConnector::builder().build().unwrap();

        let client = imap::connect((domain.as_str(), 993), domain.as_str(), &tls).unwrap();

        let imap_session = client
            .login(username, password)
            .map_err(|e| e.0).ok();

        return imap_session;
    }
}