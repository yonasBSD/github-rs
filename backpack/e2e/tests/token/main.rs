use cucumber::{given, then, when, World as _};
use github_rs_lib::get_repos;

#[derive(Debug, Default, cucumber::World)]
struct World {
    token: Option<String>,
    repos: Vec<String>,
}

#[given(expr = "{word} is found in the env")] // Cucumber Expression
async fn token_in_env(w: &mut World, env_var: String) {
    let t = std::env::var(&env_var);
    assert!(t.is_ok(), "{} was not found!", env_var);

    w.token = Some(t.unwrap());
}

#[when(regex = r"^(?:he|she|they) wants to display their repos$")]
async fn has_repos(w: &mut World) {
    let t: String = w.token.as_ref().unwrap().clone();
    let r = get_repos(t, None).await;

    assert!(
        r.is_ok(),
        "{} is an invalid token!",
        w.token.as_ref().unwrap()
    );

    w.repos = r
        .unwrap()
        .into_iter()
        .map(|repo| {
            format!(
                "{}, {}",
                repo.full_name.unwrap(),
                repo.default_branch.unwrap()
            )
        })
        .collect();

    assert!(
        !w.repos.is_empty(),
        "{} has no repos!",
        w.token.as_ref().unwrap()
    );
}

#[then("she will see all her repos")]
async fn saw_repos(w: &mut World) {
    for repo_name in w.repos.iter() {
        println!("{repo_name}");
    }

    assert!(
        !w.repos.is_empty(),
        "{} has no repos!",
        w.token.as_ref().unwrap()
    );
}

#[tokio::main]
async fn main() {
    World::cucumber()
        .init_tracing()
        .run("features/token.feature")
        .await;
}
