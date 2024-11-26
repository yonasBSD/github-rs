use clap::Parser;
use colored::Colorize;
use config::Config;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use std::collections::HashMap;
use std::error::Error;
use which::which;
use xdg;

use github_rs::*;

/// List GitHub repos
#[derive(Parser)]
#[clap(version)]
struct Cli {
    /// The organization
    #[arg(index = 1)]
    org: Option<String>, // Optional positional argument

    /// Sync with upstream
    #[arg(short = 's', long = "sync", default_value_t = false)]
    sync: bool,

    /// GitHub token
    #[arg(short = 't', long = "token")]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Parse the command-line arguments
    let cli = Cli::parse();

    let mut token: String = match cli.token {
        Some(t) => t,
        None => String::from(""),
    };

    if token.is_empty() {
        let config_path = xdg::BaseDirectories::with_prefix("")
            .unwrap()
            .get_config_home();
        match Config::builder()
            // Add in `./config/github-rs/config.toml`
            .add_source(config::File::with_name(
                format!("{}/{}", config_path.display(), "github-rs/config").as_str(),
            ))
            // Add in settings from the environment (with a prefix of APP)
            // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
            .add_source(config::Environment::with_prefix("GITHUB"))
            .build()
        {
            Ok(settings) => {
                // Read config file
                let app = settings
                    .try_deserialize::<HashMap<String, String>>()
                    .unwrap();
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
        Some(org) => get_repos(token.clone(), Some(org)).await?,
        None => get_repos(token.clone(), None).await?,
    };

    let mut count = 0;
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("reqwest"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github.v3+json"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("token {}", token.clone())).unwrap(),
    );

    for repo in results {
        if cli.sync {
            let cmd = which("gh");
            let _ = match cmd {
                Ok(_) => {}
                Err(_) => {
                    println!(
                        "{}",
                        "Error: Could not find GitHub client program `gh`.".red()
                    );
                    std::process::exit(1);
                }
            };

            count += 1;
            println!(
                "=========== Updating {} ===========\n",
                &repo.full_name.clone().unwrap()
            );

            let mut branch = HashMap::new();
            branch.insert("branch", repo.default_branch.unwrap());

            let url = format!(
                "https://api.github.com/repos/{}/merge-upstream",
                repo.full_name.unwrap()
            );
            let client = reqwest::Client::builder()
                .connection_verbose(true)
                .build()
                .expect("Client::new()");
            let resp: HashMap<String, String> = client
                .post(url)
                .headers(headers.clone())
                .json(&branch)
                .send()
                .await?
                .json::<HashMap<String, String>>()
                .await?;

            if resp.contains_key("message") {
                if resp["message"].contains("This branch is not behind the upstream")
                    || resp["message"]
                        .contains("Successfully fetched and fast-forwarded from upstream")
                {
                    println!("{} Synced.\n\n", "✓".green());
                } else {
                    let msg = &resp["message"];
                    println!("{}", format!("==> ERROR: {}\n\n", msg.red()));
                }
            } else {
                println!("==> ERROR: {:?}", resp);
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
