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
    pub fn send_message(target: Target, message: Message, connected_address: String, credentials: Credentials) {
        let target_address = EmailAddress::new(target.address).unwrap();
        let origin_address = EmailAddress::new(connected_address).unwrap();

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

        let mut message_text_vector = message.text.as_bytes().to_vec();;

        let email = SendableEmail::new(envelope, message_id, message_text_vector);

        let mut mailer = SmtpClient::new_simple("mail.gmx.net").unwrap().credentials(credentials).transport();
        // Send the email
        let result = mailer.send(email);

        if result.is_ok() {
            println!("Email sent");
        } else {
            println!("Could not send email: {:?}", result);
        }
    }
}