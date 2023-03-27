use crate::message::Message;

use lettre::{SmtpClient, SmtpTransport, Transport};
use lettre_email::EmailBuilder;

/// Creates and transmits an E-Mail.
/// # Arguments
/// * `target` - An Target object that contains the target address.
/// * `message` - An Message object.
/// * `connected_address` - The address the system is currently connected to.
pub fn send_message(
    message: Message,
    to: String,
    mut smtp_connection: SmtpTransport,
) {
    let email_builder = EmailBuilder::new()
        .to(to)
        .from(message.from)
        .subject(message.subject)
        .text(message.text);

    let email = email_builder.build().unwrap().into();

    let result = smtp_connection.send(email);

    if result.is_ok() {
        println!("Email sent");
    } else {
        println!("Could not send email: {:?}", result);
    }
}

/// Creates an SmtpTransport Object.
/// # Arguments
/// * `smtp_domain` - The domain of the SMTP server.
/// * `port` - The port on wich the SMTP server is listening.
/// * `username` - The username for the connection to the server.
/// * `password` - The password for the connection to the server.
pub fn smtp_connect(
    smtp_domain: String,
    port: u16,
    username: String,
    password: String,
) -> SmtpTransport {
    let creds = lettre::smtp::authentication::Credentials::new(username, password);
    let smtp_transport = SmtpClient::new(
        &format!("{}:{}", smtp_domain.as_str(), port),
        lettre::ClientSecurity::Wrapper(lettre::ClientTlsParameters {
            connector: tls(),
            domain: smtp_domain,
        }),
    )
        .unwrap()
        .credentials(creds)
        .transport();

    return smtp_transport;
}

///Method for generating a TlsConnector.
/// The tls connection will accept invalid certificates because of the use of greenmail for the demonstration.
fn tls() -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}
