use clap::Parser;
use colored::Colorize;
use which::which;
use github_rs::*;
use std::{io::Write, error::Error, process::Command};

/// List GitHub repos
#[derive(Parser)]
struct Cli {
    /// The organization
    #[arg(index = 1)]
    org: Option<String>, // Optional positional argument

    /// Sync with upstream
    #[arg(short = 's', long = "sync", default_value_t=false)]
    sync: bool,
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

    let mut count = 0;
    for repo in results {
        if cli.sync {
            let cmd = which("gh");
            let _ = match cmd {
                Ok(_) => { },
                Err(_) => {
                    println!("{}", "Error: Could not find GitHub client program `gh`.".red());
                    std::process::exit(1);
                }
            };

            count += 1;
            println!("=========== Updating {} ===========\n", &repo.full_name.clone().unwrap());

            let output = Command::new("gh")
                .arg("repo")
                .arg("sync")
                .arg(repo.full_name.unwrap())
                .output()
                .expect("failed to execute gh");

            std::io::stdout().write_all(&output.stdout).unwrap();
            std::io::stderr().write_all(&output.stderr).unwrap();

            if output.status.success() {
                println!("{} Syned.\n\n", "✓".green());
            } else {
                println!("==> ERROR: Merge conflicts\n\n");
            }
        } else {
            println!(
                "{}, {}",
                repo.full_name.unwrap(),
                repo.default_branch.unwrap()
            );
        }
    }

    if count > 0 {
        println!("Total updates: {}", count);
    }

    Ok(())
}
