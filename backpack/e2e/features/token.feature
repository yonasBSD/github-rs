# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 yonasBSD

Feature: List all GitHub repos.

  @eating
  Scenario: Runs something
    Given GITHUB_TOKEN is found in the env
    When she wants to display their repos
    Then she will see all her repos
