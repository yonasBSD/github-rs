use clap::Parser;
use octocrab::Octocrab;
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
    let octocrab = Octocrab::builder().personal_token(token).build()?;

    // Get the value of the positional argument (if provided)
    let page = match cli.org {
        Some(org) => {
            octocrab
                .current()
                .list_repos_for_authenticated_user(Some(org))
                .type_("owner")
                .sort("updated")
                .per_page(100)
                .send()
                .await?
        }
        None => {
            octocrab
                .current()
                .list_repos_for_authenticated_user(None)
                .type_("owner")
                .sort("updated")
                .per_page(100)
                .send()
                .await?
        }
    };

    let results = octocrab.all_pages(page).await.unwrap();

    for repo in results {
        println!(
            "{}, {}",
            repo.full_name.unwrap(),
            repo.default_branch.unwrap()
        );
    }

    Ok(())
}
