use anyhow::Result;
use vergen::{vergen, Config};

fn main() -> Result<()> {
    // Generate all the environment variables we will latter need
    vergen(Config::default())
}
