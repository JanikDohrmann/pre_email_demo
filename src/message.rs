pub mod message {

    #[derive(Clone)]
    pub struct Message {
        pub subject: String,
        pub from: String,
        pub text: String,
    }

    pub fn build_message(subject: String, from: String, text: String) -> Message {
        Message {
            subject,
            from,
            text,
        }
    }
}
