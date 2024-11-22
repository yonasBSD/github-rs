use octocrab::models::Repository;
use octocrab::Octocrab;
use std::error::Error;

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(multiply(2, 2), 4);
    }

    #[tokio::test]
    async fn repos() -> Result<(), Box<dyn Error>> {
        let token = std::env::var("GITHUB_TOKEN").expect("GITHUB_TOKEN env variable is required");
        let repos = get_repos(token, None).await?;

        assert!(repos.len() > 0);

        Ok(())
    }
}
