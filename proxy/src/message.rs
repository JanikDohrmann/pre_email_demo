/// The message stores the important information of an e-mail
#[derive(Clone)]
pub struct Message {
    pub subject: String,
    pub from: String,
    pub text: String,
}

/// Creates a message
/// # Arguments
/// * `subject` - The subject of the message.
/// * `from` - The origin of the message.
/// * `text` - The text of the message.
/// # Return
/// Returns a target.
pub fn build_message(subject: String, from: String, text: String) -> Message {
    Message {
        subject,
        from,
        text,
    }
}
