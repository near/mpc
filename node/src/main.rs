use tracing::init_logging;

pub mod key_generation;
pub mod network;
pub mod primitives;
mod tracing;
pub mod tracking;
pub mod triple;

fn main() {
    init_logging();
    println!("Hello, world!");
}
