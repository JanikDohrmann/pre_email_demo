pub mod message_loader {
    use crate::message::message::{Message, build_message};
    use self::imap::Session;
    use native_tls::TlsStream;
    use std::net::TcpStream;

    extern crate imap;

    extern crate pest;


    use pest::Parser;

    #[derive(Parser)]
    #[grammar = "email.pest"]
    struct EMailParser;

    pub fn load_message(mut session: Session<TlsStream<TcpStream>>) -> String{
        session.select("INBOX");

        String::from("test")
    }

    pub fn parse_message(message: String)  -> Message {
        let pairs = EMailParser::parse(Rule::from, &message).unwrap_or_else(|e| panic!("{}", e));
        // Because ident_list is silent, the iterator will contain idents
        for pair in pairs {

            let span = pair.clone().into_span();
            // A pair is a combination of the rule which matched and a span of input
            println!("Rule:    {:?}", pair.as_rule());
            println!("Span:    {:?}", span);
            println!("Text:    {}", span.as_str());

            // A pair can be converted to an iterator of the tokens which make it up:
            for inner_pair in pair.into_inner() {
                let inner_span = inner_pair.clone().into_span();
                match inner_pair.as_rule() {
                    Rule::alia => println!("Alias:  {}", inner_span.as_str()),
                    Rule::address => println!("Addresse:   {}", inner_span.as_str()),
                    _ => unreachable!()
                };
            }
        }
        build_message("Test".parse().unwrap(), "test".parse().unwrap(), "test".parse().unwrap())
    }

    /// Creates a authorized session that is connected to an IMAP server.
    /// domain: The address of the IMAP server.
    /// username: The username on that server for the login.
    /// password: the password on that server for the login.
    pub fn connect(domain: String, username: String, password: String) -> Session<TlsStream<TcpStream>> {
        let tls = native_tls::TlsConnector::builder().build().unwrap();

        let client = imap::connect((domain.as_str(), 993), domain.as_str(), &tls).unwrap();

        let imap_session = client
            .login(username, password)
            .map_err(|e| e.0).ok().unwrap();

        return imap_session;
    }
}