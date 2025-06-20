# Changelog

All notable changes to this project will be documented in this file.

## [unreleased]

### 🚀 Features

- Use tracing for logs. (#25)

### 🐛 Bug Fixes

- Cross build should use nightly.

### 💼 Other

- _(deps)_ Bump github/codeql-action from 3.27.5 to 3.29.0 (#29)
- _(deps)_ Bump ossf/scorecard-action from 2.4.1 to 2.4.2 (#27)
- _(deps)_ Bump dtolnay/rust-toolchain (#26)

### 🧪 Testing

- Add cucumber BDD testing. (#31)

### ⚙️ Miscellaneous Tasks

- Add Codacy config file.
- Add repo activity to README.md
- Create new end-to-end step in testing workflow. (#32)

### 🛡️ Security

- _(deps)_ Bump step-security/harden-runner from 2.10.2 to 2.12.1 (#30)

## [1.1.0] - 2025-06-15

### 🚀 Features

- List repos of an organization.
- Create release-packaging workflow
- Add git-cliff config file.
- Add --sync flag.
- Add config file.
- Remove dependency on `gh` cli.
- Add --version
- Add codacy code coverage. (#16)
- Add conventional commits and spell checking to lints.
- Create GitHub code review suggestions.

### 🐛 Bug Fixes

- Actions-rs/toolchain in coverage workflow
- Actions-rs/toolchain in test workflow
- Switch to dtolnay/rust-toolchain
- Switch to nightly toolchain in testing workflow
- Use marketplace workflow to install grcov
- Generate results.xml in testing workflow
- Remove obsolete options in linting workflow
- Add read permissions to test workflow
- Update nfpm package config.
- Run Cross Build only if Test with Code Coverage passes.
- Use jq instead of gojq.
- Use yonasBSD/cargo2junit in test-with-coverage.yaml
- Xdg fix (#12)
- Update GITHUB_TOKEN in cross build workflow. (#19)
- Switch xdg to directories crate for Windows support. (#20)
- Fix config path on Mac and Windows. (#21)
- SonarQube warnings. (#22)
- Windows depends on GITHUB_TOKEN env variable. (#23)
- Specify files to spell-checker.
- Remove spell-checker.

### 💼 Other

- _(deps)_ Bump mozilla-actions/sccache-action from 0.0.5 to 0.0.6 (#1)
- _(deps)_ Bump mozilla-actions/sccache-action from 0.0.6 to 0.0.7 (#3)
- _(deps)_ Update config requirement from 0.14.1 to 0.15.4 (#4)
- _(deps)_ Update colored requirement from 2.1.0 to 3.0.0 (#5)
- _(deps)_ Bump mozilla-actions/sccache-action from 0.0.7 to 0.0.8 (#6)
- _(deps)_ Bump mozilla-actions/sccache-action from 0.0.8 to 0.0.9 (#7)
- _(deps)_ Update duct requirement from 0.13.5 to 1.0.0 (#9)
- _(deps)_ Update xdg requirement from 2.5.2 to 3.0.0 (#8)
- _(deps)_ Update which requirement from 7.0.0 to 8.0.0 (#10)

### 🚜 Refactor

- Fix formatting.
- Remove lints from Coverage workflow
- Fix clippy warnings.
- Use dtolnay/rust-toolchain in coverage workflow
- Fix formatting.
- Fix formatting.
- Improve code coverage. (#14)
- Fix codacy issues. (#18)

### ⚙️ Miscellaneous Tasks

- Initial commit
- Add tests.
- Update and rename coverage.yaml to cross-build.yaml
- Move xtask to testing workflow
- Update and rename test.yaml to test-with-coverage.yaml
- Add changelog.
- Update workflows.
- Update workflows.
- Update README.md
- Hide Matrix badge for faster page load.
- Upload tests to CodeCov. (#13)
- Add badges to README.md (#15)
- Create SECURITY.md

## [1.0.0] - 2024-11-19

### 🚀 Features

- List repos of an organization.
- Create release-packaging workflow

### 🐛 Bug Fixes

- Actions-rs/toolchain in coverage workflow
- Actions-rs/toolchain in test workflow
- Switch to dtolnay/rust-toolchain
- Switch to nightly toolchain in testing workflow
- Use marketplace workflow to install grcov
- Generate results.xml in testing workflow
- Remove obsolete options in linting workflow
- Add read permissions to test workflow
- Update nfpm package config.

### 💼 Other

- _(deps)_ Bump mozilla-actions/sccache-action from 0.0.5 to 0.0.6 (#1)

### 🚜 Refactor

- Fix formatting.
- Fix clippy warnings.
- Use dtolnay/rust-toolchain in coverage workflow

### ⚙️ Miscellaneous Tasks

- Add tests.
- Move xtask to testing workflow
