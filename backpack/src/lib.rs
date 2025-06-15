use clap::Parser;
use colored::Colorize;
use config::Config;
use octocrab::models::Repository;
use octocrab::Octocrab;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use std::{collections::HashMap, error::Error};
use which::which;
use directories::ProjectDirs;

/// List GitHub repos
#[derive(Parser)]
#[clap(version)]
pub struct Cli {
    /// The organization
    #[arg(index = 1)]
    pub org: Option<String>, // Optional positional argument

    /// Sync with upstream
    #[arg(short = 's', long = "sync", default_value_t = false)]
    pub sync: bool,

    /// GitHub token
    #[arg(short = 't', long = "token")]
    pub token: Option<String>,
}

/// Multiplies two integers
pub fn multiply(a: i32, b: i32) -> i32 {
    a * b
}

/// List GitHub repositories
pub async fn get_repos(
    token: String,
    org: Option<String>,
) -> Result<Vec<Repository>, Box<dyn Error>> {
    let octocrab = Octocrab::builder().personal_token(token).build()?;

    // Validate token permissions early. Fail fast if user info is not returned.
    let user = octocrab.current().user().await?;
    if user.login.is_empty() {
        return Err("Invalid or insufficient token permissions".into());
    }

    // Get the value of the positional argument (if provided)
    let page = match org {
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

    Ok(octocrab.all_pages(page).await.unwrap())
}

pub async fn get_token(token: String) -> Result<String, Box<dyn Error>> {
    if !token.is_empty() {
        return Ok(token);
    }

    let base_path = ProjectDirs::from("org", "yonasBSD",  "github-rs").expect("Get config path");
    let config_path = base_path.config_dir();

    let m_token = match Config::builder()
        // Add in `./config/github-rs/config.toml`
        .add_source(config::File::with_name(
            format!("{}/{}", config_path.display(), "/config").as_str(),
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
                app["token"].clone()
            } else {
                println!("{}", "Error: Could not find GitHub token".red());
                std::process::exit(1)
            }
        }

        Err(_) => {
            println!("{}", "Error: Could not find GitHub token".red());
            std::process::exit(1);
        }
    };

    Ok(m_token)
}

pub fn make_headers(token: String) -> HeaderMap {
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

    headers
}

pub async fn make_response(
    client: reqwest::Client,
    url: String,
    headers: HeaderMap,
    branch: HashMap<&str, String>,
) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let map = client
        .post(url)
        .headers(headers.clone())
        .json(&branch)
        .send()
        .await?
        .json::<HashMap<String, String>>()
        .await?;

    Ok(map)
}

pub async fn update_repos(
    repos: Vec<Repository>,
    sync: bool,
    token: String,
) -> Result<u32, Box<dyn Error>> {
    let mut count = 0;

    for repo in repos {
        if !sync {
            println!(
                "{}, {}",
                repo.full_name.unwrap(),
                repo.default_branch.unwrap()
            );

            continue;
        }

        let cmd = which("gh");
        match cmd {
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

        let headers: HeaderMap = make_headers(token.clone());
        let resp: HashMap<String, String> = make_response(client, url, headers, branch).await?;

        if resp.contains_key("message") {
            if resp["message"].contains("This branch is not behind the upstream")
                || resp["message"].contains("Successfully fetched and fast-forwarded from upstream")
            {
                println!("{} Synced.\n\n", "✓".green());
            } else {
                let msg = &resp["message"];
                println!("==> ERROR: {}\n\n", msg.red());
            }
        } else {
            println!("==> ERROR: {:?}", resp);
        }
    }

    Ok(count)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(multiply(2, 2), 4);
    }

    #[tokio::test]
    async fn test_get_repos() -> Result<(), Box<dyn Error>> {
        let token = std::env::var("GITHUB_TOKEN").expect("GITHUB_TOKEN env variable is required");
        let repos_for_user = get_repos(token.clone(), None).await?;
        let repos_for_org = get_repos(token.clone(), Some(String::from("yonasBSD"))).await?;

        assert!(
            repos_for_user.len() > 0,
            "Able to fetch personal repositories"
        );
        assert!(
            repos_for_org.len() > 0,
            "Able to fetch organization repositories"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_get_token() -> Result<(), Box<dyn Error>> {
        // Test supplied token is used
        let token = String::from("some-token");
        let token_result = get_token(token).await?;

        assert!(
            token_result == "some-token",
            "Passing get_token() a non-empty token results in it being used."
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_get_empty_token() -> Result<(), Box<dyn Error>> {
        // Write config.toml file
        use std::io::Write;
        use std::path::Path;

        // Create config.toml if it doesn't exist
        let path = format!(
            "{}/.config/github-rs/config.toml",
            std::env::var("HOME").unwrap()
        );
        let path = Path::new(&path);
        if !path.exists() {
            // Create the full path
            let prefix = path.parent().unwrap();
            std::fs::create_dir_all(prefix).unwrap();

            // Write the config.toml file
            let mut output = std::fs::File::create(path)?;
            let line = "token = \"some-token\"";
            let _ = write!(output, "{}", line);
        }

        // Test empty token results in config file being used
        let empty_token = String::from("");
        let empty_token_result = get_token(empty_token).await?;

        assert!(
            empty_token_result.len() > 0,
            "Passing get_token() an empty token results in config file being used."
        );

        Ok(())
    }

    #[test]
    fn test_make_headers() -> Result<(), Box<dyn Error>> {
        let headers = make_headers(String::from("some-token"));

        assert!(
            headers.contains_key(USER_AGENT),
            "Headers contains USER_AGENT"
        );
        assert!(
            headers.contains_key(CONTENT_TYPE),
            "Headers contains CONTENT_TYPE"
        );
        assert_eq!(
            headers[CONTENT_TYPE], "application/json",
            "Headers contains CONTENT_TYPE of type application/json"
        );
        assert!(headers.contains_key(ACCEPT), "Headers contains ACCEPT");
        assert_eq!(
            headers[ACCEPT], "application/vnd.github.v3+json",
            "Headers contains ACCEPT of type application/vnd.github.v3+json"
        );
        assert!(
            headers.contains_key(AUTHORIZATION),
            "Headers contains AUTHORIZATION"
        );
        assert!(
            headers[AUTHORIZATION]
                .to_str()
                .unwrap()
                .contains("some-token"),
            "Headers contains AUTHORIZATION of type some-token"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_update_repos() -> Result<(), Box<dyn Error>> {
        let mut count: u32;
        let repos: Vec<Repository> =
            serde_json::from_str(include_str!("../../tests/resources/user_repositories.json"))
                .unwrap();
        let empty_repos: Vec<Repository> = Vec::new();
        let token: String = String::from("some-token");

        // Test with empty list of repos
        count = update_repos(empty_repos.clone(), false, token.clone())
            .await
            .expect("update repos");
        assert_eq!(
            count, 0,
            "Pass empty vector to update_repos() without sync."
        );

        count = update_repos(empty_repos.clone(), true, token.clone())
            .await
            .expect("update repos");
        assert_eq!(count, 0, "Pass empty vector to update_repos() with sync.");

        // Test with some repos
        count = update_repos(repos.clone(), false, token.clone())
            .await
            .expect("update repos");
        assert_eq!(count, 0, "Pass vector to update_repos() without sync.");

        count = update_repos(repos.clone(), true, token.clone())
            .await
            .expect("update repos");
        assert_eq!(count, 2, "Pass vector to update_repos() with sync.");

        Ok(())
    }
}
