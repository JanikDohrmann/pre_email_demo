use crate::message_loader::message_loader::parse_message;

mod message;
mod message_loader;
mod target;
mod command;
mod message_transmitter;
mod re_encryption;

#[macro_use]
extern crate pest_derive;

fn main() {

    parse_message("From: \"GMX Kundenmanagement\" <mailings@system.gmx.net>".parse().unwrap());
}
