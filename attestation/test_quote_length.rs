use std::env;

fn main() {
    let valid_quote_hex = include_str!("tee_authority_quote.txt");
    println!("Quote length: {}", valid_quote_hex.len());
}
