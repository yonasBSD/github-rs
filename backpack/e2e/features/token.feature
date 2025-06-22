Feature: List all GitHub repos.

  @eating
  Scenario: Runs something
    Given GITHUB_TOKEN is found in the env
    When she wants to display their repos
    Then she will see all her repos
