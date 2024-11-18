use clap::Parser;
use github_rs::*;
use std::error::Error;

/// List GitHub repos
#[derive(Parser)]
struct Cli {
    /// The organization
    #[arg(index = 1)]
    org: Option<String>, // Optional positional argument
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Parse the command-line arguments
    let cli = Cli::parse();

    let token = std::env::var("GITHUB_TOKEN").expect("GITHUB_TOKEN env variable is required");

    // Get the value of the positional argument (if provided)
    let results = match cli.org {
        Some(org) => get_repos(token, Some(org)).await?,
        None => get_repos(token, None).await?,
    };

    for repo in results {
        println!(
            "{}, {}",
            repo.full_name.unwrap(),
            repo.default_branch.unwrap()
        );
    }

    Ok(())
}
