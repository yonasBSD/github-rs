use clap::Parser;
use colored::Colorize;
use which::which;
use config::Config;
use xdg;
use std::collections::HashMap;
use std::{io::Write, error::Error, process::Command};

use github_rs::*;

/// List GitHub repos
#[derive(Parser)]
struct Cli {
    /// The organization
    #[arg(index = 1)]
    org: Option<String>, // Optional positional argument

    /// Sync with upstream
    #[arg(short = 's', long = "sync", default_value_t=false)]
    sync: bool,

    /// GitHub token
    #[arg(short = 't', long = "token")]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Parse the command-line arguments
    let cli = Cli::parse();

    let mut token: String = match cli.token {
        Some(t) => t,
        None => String::from(""),
    };

    if token.is_empty() {
        let config_path = xdg::BaseDirectories::with_prefix("").unwrap().get_config_home();
        match Config::builder()
            // Add in `./config/github-rs/config.toml`
            .add_source(config::File::with_name(format!("{}/{}", config_path.display(), "github-rs/config").as_str()))
            // Add in settings from the environment (with a prefix of APP)
            // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
            .add_source(config::Environment::with_prefix("GITHUB"))
            .build() {
            Ok(settings) => {
                // Read config file
                let app = settings.try_deserialize::<HashMap<String, String>>().unwrap();
                if app.contains_key("token") {
                    token = app["token"].clone();
                } else {
                    println!("{}", "Error: Could not find GitHub token".red());
                    std::process::exit(1);
                }
            }
            Err(_) => {
                //token = std::env::var("GITHUB_TOKEN").expect("GITHUB_TOKEN env variable is required");
                println!("{}", "Error: Could not find GitHub token".red());
                std::process::exit(1);
            }
        };
    }

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
