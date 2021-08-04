pub mod message_transmitter {
    use crate::target::target::Target;
    use crate::message::message::Message;
    use lettre_email::EmailBuilder;

    pub fn send_message(target: Target, message: Message, connected_address: String) {
        let email = EmailBuilder::new()
            // Addresses can be specified by the tuple (email, alias)
            .to(target.address)
            // ... or by an address only
            .from(connected_address)
            .subject(message.subject)
            .text(message.text)
            .build()
            .unwrap();

        // Open a local connection on port 25
        let mut mailer = SmtpTransport::builder_unencrypted_localhost().unwrap()
            .build();
        // Send the email
        let result = mailer.send(&email);

        if result.is_ok() {
            println!("Email sent");
        } else {
            println!("Could not send email: {:?}", result);
        }
    }
}