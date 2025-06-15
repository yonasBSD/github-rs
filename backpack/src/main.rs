use clap::Parser;
use std::error::Error;

use github_rs::{get_repos, get_token, update_repos, Cli};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Parse the command-line arguments
    let cli = Cli::parse();
    let token = get_token(cli.token.unwrap_or_default()).await?;

    // Get the value of the positional argument (if provided)
    let repos = match cli.org {
        Some(org) => get_repos(token.clone(), Some(org)).await?,
        None => get_repos(token.clone(), None).await?,
    };

    let count = update_repos(repos, cli.sync, token.clone()).await?;
    if count > 0 {
        println!("Total updates: {}", count);
    }

    Ok(())
}
