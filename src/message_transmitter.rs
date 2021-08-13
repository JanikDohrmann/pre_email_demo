pub mod message_transmitter {
    use crate::target::target::Target;
    use crate::message::message::Message;

    use lettre::{SmtpTransport, SmtpClient, Transport, EmailAddress, Envelope, SendableEmail};
    use lettre_email::EmailBuilder;
    use std::path::Path;
    use chrono::Utc;
    use lettre::smtp::authentication::Credentials;

    /// Creates and transmits an E-Mail.
    /// target: an Target object that contains the target address.
    /// message: an Message object.
    /// connected_address: The address the system is currently connected to.
    /// credentials: The credentials to log in into the smtp server.
    pub fn send_message(target: Target, message: Message, connected_address: String, credentials: Credentials, smtp_domain: String) {
        let email_builder = EmailBuilder::new()
            .to(target.address)
            .from(connected_address)
            .subject(message.subject)
            .text(message.text);

        let email = email_builder.build().unwrap().into();

        let mut mailer = SmtpClient::new_simple(smtp_domain.as_str()).unwrap().credentials(credentials).transport();

        let result = mailer.send(email);

        if result.is_ok() {
            println!("Email sent");
        } else {
            println!("Could not send email: {:?}", result);
        }
    }
}