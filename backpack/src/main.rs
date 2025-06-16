#![feature(coverage_attribute)]

#[cfg(not(feature = "coverage"))]
use clap::Parser;
use github_rs::{get_repos, get_token, update_repos, Cli};
use std::error::Error;
use terminal_banner::Banner;

#[cfg(not(feature = "coverage"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Set environment for logging configuration
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use RUST_LOG env variable
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // Use a more compact, abbreviated log format
        .compact()
        // Display source code file paths
        .with_file(true)
        // Display source code line numbers
        .with_line_number(true)
        // Display the thread ID an event was recorded on
        .with_thread_ids(true)
        // Don't display the event's target (module path)
        .with_target(false)
        // ...
        //.with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        // Build the subscriber
        .finish();

    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber)?;

    tracing::debug!("Logging initialized!");
    tracing::trace!("Tracing initialized!");
    tracing::debug!("Ready to begin...");

    if std::env::var("RUST_LOG").unwrap().to_lowercase() == "debug" {
        let banner = Banner::new()
            .text("Welcome to github-rs!".into())
            .text("Easily sync all your forked repos.".into())
            .render();

        println!("{banner}");
    }

    // Parse the command-line arguments
    let cli = Cli::parse();
    tracing::trace!(
        org = cli.org,
        sync = cli.sync,
        token = cli.token,
        "Parsed command line arguments"
    );

    if cli.sync {
        tracing::warn!("Sync enabled. This might take a while.");
    }

    let token = get_token(cli.token.unwrap_or_default()).await?;
    tracing::trace!(token = token, "Got GitHub token");

    // Get the value of the positional argument (if provided)
    let repos = match cli.org {
        Some(org) => get_repos(token.clone(), Some(org)).await?,
        None => get_repos(token.clone(), None).await?,
    };

    let count = update_repos(repos, cli.sync, token.clone()).await?;
    tracing::trace!(count = count, "Got count of GitHub repos updated");

    if count > 0 {
        println!("Total updates: {count}");
    }

    Ok(())
}
