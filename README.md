<!--
SPDX-FileCopyrightText: 2025 yonasBSD

SPDX-License-Identifier: MIT
-->

# Rust CI with GitHub Actions

![Linting workflow](https://github.com/yonasBSD/github-rs/actions/workflows/lint.yaml/badge.svg)
![testing workflow](https://github.com/yonasBSD/github-rs/actions/workflows/test-with-coverage.yaml/badge.svg)
![packaging](https://github.com/yonasBSD/github-rs/actions/workflows/release-packaging.yaml/badge.svg)
![cross-build](https://github.com/yonasBSD/github-rs/actions/workflows/cross-build.yaml/badge.svg)
[![codecov](https://codecov.io/gh/yonasBSD/github-rs/branch/main/graph/badge.svg?token=1R5SBEX51H)](https://codecov.io/gh/yonasBSD/github-rs)

<!--[![ghcr.io](https://img.shields.io/badge/ghcr.io-download-blue)](https://github.com/yonasBSD/github-rs/pkgs/container/github-rs)-->
<!--[![Docker Pulls](https://img.shields.io/docker/pulls/github-rs/example.svg)](https://hub.docker.com/r/github-rs/example)-->
<!--[![Quay.io](https://img.shields.io/badge/Quay.io-download-blue)](https://quay.io/repository/github-rs/example)-->

![Security Audit](https://github.com/yonasBSD/github-rs/actions/workflows/security.yaml/badge.svg)
![Scorecard Audit](https://github.com/yonasBSD/github-rs/actions/workflows/scorecard.yaml/badge.svg)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/1545c22f5f484e4ea9bf6ed4c58f0ee4)](https://app.codacy.com/gh/yonasBSD/github-rs/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=yonasBSD_github-rs&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=yonasBSD_github-rs)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=yonasBSD_github-rs&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=yonasBSD_github-rs)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=yonasBSD_github-rs&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=yonasBSD_github-rs)

![GitHub last commit](https://img.shields.io/github/last-commit/yonasBSD/github-rs)
[![Dependency Status](https://deps.rs/repo/github/yonasBSD/github-rs/status.svg)](https://deps.rs/repo/github/yonasBSD/github-rs)
[![GitHub Release](https://img.shields.io/github/release/yonasBSD/github-rs.svg)](https://github.com/yonasBSD/github-rs/releases/latest)
[![License](https://img.shields.io/github/license/yonasBSD/github-rs.svg)](https://github.com/yonasBSD/github-rs/blob/main/LICENSE.txt)

<!--[![Matrix Chat](https://img.shields.io/matrix/vaultwarden:matrix.org.svg?logo=matrix)](https://matrix.to/#/#vaultwarden:matrix.org)-->

## Table of Contents

1. [Workflows](#workflows)
   - [Check and Lint (check-and-lint.yaml)](#check-and-lint)
   - [Test with Code Coverage (test.yaml)](#test-with-code-coverage)
   - [Release Packaging (release-packaging.yaml)](#release-packaging)
2. [How to Use](#how-to-use)

## Workflows

The CI process is separated into 3 workflows: Check and Lint, Test, and Release Packaging.

All jobs run on `ubuntu-latest`, and are run in parallel.

All jobs use [actions/checkout](https://github.com/actions/checkout) and [actions-rs/toolchain](https://github.com/actions-rs/toolchain).

<a name="check-and-lint"></a>

### Check and Lint (check-and-lint.yaml)

This workflow checks for compiler errors and code style inconsistencies.

It runs on pull requests and main branch push.

#### 📋 Check job

This job runs `cargo check` on the stable toolchain.

It checks if there are compiler errors.

#### 📋 Rustfmt job

This job runs [rustfmt](https://github.com/rust-lang/rustfmt) with the `--check` option through `cargo fmt` on the stable toolchain.

By default, it checks inconsistencies with the [Rust style guide](https://github.com/rust-lang-nursery/fmt-rfcs/blob/master/guide/guide.md).
You can add a `rustfmt.toml` or `.rustfmt.toml` to configure the style.

#### 📋 Clippy job

This job runs [clippy](https://github.com/rust-lang/rust-clippy) on the stable toolchain through [actions-rs/clippy-check@v1](https://github.com/actions-rs/clippy-check).

You can add a `clippy.toml` or `.clippy.toml` to configure the style.

- The action outputs result (**Clippy Output** added to a random workflow), and
- For pull requests, it adds annotations on the diff.

### Test with Code Coverage (test.yaml)

This workflow run tests, outputs test results, publishes code coverage results on [CodeCov](https://codecov.io/).
Publishing test results and code coverage data is in one job to avoid running the tests twice.
It runs on pull requests and main branch push.

#### 📋 Test job

This job:

1. Caches dependencies,
2. Runs tests and generate test results and code coverage data,
3. Uploads test results, and
4. Uploads to CodeCov.

Environment variables used in this job:

- `PROJECT_NAME_UNDERSCORE` - project name with hyphens(-) as underscores(\_) needed for code coverage
- `CARGO_INCREMENTAL`, `RUSTFLAGS`, `RUSTDOCFLAGS` - added to `CARGO_OPTIONS` in cargo test needed for code coverage

Steps:

1. Cache dependencies.
   It caches download and compilation of dependencies based on a hash of Cargo.lock to shorten build time
   with [actions/cache@v2](https://github.com/actions/cache).
   - The key is `${{ runner.os }}-build-${{ env.cache-name }}-${{ hashFiles('Cargo.lock') }}`
     where `env.cache-name`: `cache-dependencies`.
   - Cache is stored at the end of the job on cache miss. Cache is not updated on cache hit.

2. Generate test results and code coverage data.
   1. It installs [cargo2junit](https://github.com/johnterickson/cargo2junit) needed for formatting the test result and [grcov](https://github.com/mozilla/grcov) for code coverage.
   2. It runs `cargo test` in the nightly toolchain.
   - `$CARGO_OPTIONS` includes `CARGO_INCREMENTAL`, `RUSTFLAGS`, and `RUSTDOCFLAGS` options needed for code coverage.
   - `-Z unstable-options --format json` formats the test result into json.
   - ` | cargo2junit > results.xml` converts the json result into junit format for `EnricoMi/publish-unit-test-result-action` to understand and saves it as `results.xml`.
   4. It generates code coverage data in lcov format through `grcov` saved as `lcov.info`.

3. Upload test results.
   It uploads the test result (`results.xml`) through [EnricoMi/publish-unit-test-result-action@v1](https://github.com/EnricoMi/publish-unit-test-result-action).
   - The action outputs the test result (**Test Results** added to a random workflow).
   - For pull requests, the action adds a comment containing the test results.

4. Upload to CodeCov.
   It uploads the code coverage result (`lcov.info`) to CodeCov through [codecov/codecov-action@v1](https://github.com/codecov/codecov-action).
   - For pull requests, the actions adds a comment containing the code coverage report.
   - For private repositories, add your token from CodeCov repository setting on GitHub Secrets and uncomment the line: `token: ${{ secrets.CODECOV_TOKEN }}`.

### Release Packaging (release-packaging.yaml)

This workflow builds the package in release mode and uploads resulting file as a GitHub artifact.
It runs on main branch push.

#### 📋 Release Packaging job

This job builds the project in release mode and uploads the binary as an artifact through [actions/upload-artifact@v2](https://github.com/actions/upload-artifact).

The binary `target/release/${{ env.PROJECT_NAME_UNDERSCORE }}` is uploaded as `${{ env.PROJECT_NAME_UNDERSCORE }}`.

## How to Use

1. Replace the value of `PROJECT_NAME_UNDERSCORE` with your project name (replace hyphens(-) as underscores(\_)).

2. Customize when to call the workflows (like branch names)

3. Customize options:
   - Configure rustfmt and clippy with TOML files.
   - Customize cargo test options (like excluding certain tests).
   - Configure paths to upload from release build (like uploading multiple binary artifacts).

Notes:

- `secrets.GITHUB_TOKEN` is needed by some actions to create GitHub checks & annotations. it is added automatically by GitHub.
- uses cache for GitHub actions.
- clippy html output and test result output are added to random workflows for a certain commit due to limitations in the GitHub Actions API.

## Repo Activity

![Alt](https://repobeats.axiom.co/api/embed/a6d7cdb3696aab81174ef5054ae1229f70ed2134.svg "Repobeats analytics image")
