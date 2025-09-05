mod inversion;
mod lagrange;

fn main() {
    lagrange::benches();
    inversion::benches();
}
