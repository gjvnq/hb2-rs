use anyhow::Result;
use vergen::{Config, vergen};

fn main() -> Result<()> {
  // Generate all the environment variables we will latter need
  vergen(Config::default())
}