use std::fs;

use anyhow::anyhow;
use clap::{Parser, Subcommand};
use toml_edit::DocumentMut;
use xshell::{Shell, cmd};

type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

#[derive(Parser)]
struct Xtask {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Switch matrix-rust-sdk to the latest git commit.
    UnstableRustSdk,
}

fn main() -> Result<()> {
    match Xtask::parse().cmd {
        Command::UnstableRustSdk => unstable_rust_sdk(),
    }
}

fn unstable_rust_sdk() -> Result<()> {
    // Things which DON'T work here include:
    //
    // - A simple `cargo update`. That only works while if `Cargo.toml` is
    //   configured to use matrix-rust-sdk` from the `main` branch of git. Once we
    //   switch to a release version, `cargo update` does nothing.
    //
    //  - Adding a `[patch]` section to `.cargo/config.toml` (followed by `cargo
    //    update`). That works ok until the Rust SDK gets a version bump, at which
    //    point the patch is deemed incompatible with the version in `Cargo.lock`.
    //
    // So, let's edit the `Cargo.toml`.

    let cargo_toml = "Cargo.toml";
    if let Some(modified_doc) = update_cargo_toml(&fs::read_to_string(cargo_toml)?)? {
        fs::write(cargo_toml, modified_doc)?;
    }
    cargo_update()?;
    Ok(())
}

/// Update the `matrix-rust-sdk` entries in `Cargo.toml`, so that they use a
/// `git` uri, with no `version` or `rev`, meaning that we will pull the latest
/// version from git.
///
/// Returns `Some(modified_doc)` if the toml needs an update, otherwise `None`.
fn update_cargo_toml(doc: &str) -> Result<Option<String>> {
    let mut doc: DocumentMut = doc.parse()?;

    let dependencies = doc["dependencies"].as_table_mut().expect("'dependencies' not a table");

    // Search for dependencies whose name starts 'matrix-sdk', and edit them
    let mut modified = false;
    for (name, dep) in dependencies.iter_mut().filter(|(name, _)| name.starts_with("matrix-sdk-")) {
        let table = dep.as_table_like_mut().ok_or(anyhow!("Dependency '{name}' not a table"))?;

        if table.contains_key("version") || !table.contains_key("git") || table.contains_key("rev")
        {
            println!("Updating dependency {name} in Cargo.toml");
            table.remove("rev");
            table.remove("version");
            table.insert("git", "https://github.com/matrix-org/matrix-rust-sdk".into());
            modified = true;
        }
    }

    if modified {
        Ok(Some(doc.to_string()))
    } else {
        Ok(None)
    }
}

fn cargo_update() -> Result<()> {
    let sh = Shell::new()?;
    cmd!(sh, "cargo update").run()?;
    Ok(())
}


#[cfg(test)]
mod tests {
    #[test]
    pub fn test_update_cargo_toml_from_git_rev() {
        let input = r#"
[package]
name = "matrix-sdk-crypto-wasm"

[dependencies]
anyhow = "1.0.68"
matrix-sdk-common = { git = "https://github.com/matrix-org/matrix-rust-sdk", rev = "0f73ffde6", features = ["js"] }
matrix-sdk-indexeddb = { git = "https://github.com/matrix-org/matrix-rust-sdk", rev = "0f73ffde6", default-features = false, features = ["e2e-encryption"] }
matrix-sdk-qrcode = { git = "https://github.com/matrix-org/matrix-rust-sdk", rev = "0f73ffde6", optional = true }
wasm-bindgen-test = "0.3.37"

[build-dependencies]
vergen-gitcl = { version = "1.0.0", features = ["build"] }

[dependencies.matrix-sdk-crypto]
git = "https://github.com/matrix-org/matrix-rust-sdk"
rev = "0f73ffde6"
default-features = false
features = ["js", "automatic-room-key-forwarding"]
"#;
        let doc = super::update_cargo_toml(input).unwrap().unwrap();
        insta::assert_snapshot!(doc)
    }

    #[test]
    pub fn test_update_cargo_toml_from_release() {
        let input = r#"
[package]
name = "matrix-sdk-crypto-wasm"

[dependencies]
anyhow = "1.0.68"
matrix-sdk-common = { version = "0.11.1", features = ["js"] }
matrix-sdk-indexeddb = { version = "0.11.1", default-features = false, features = ["e2e-encryption"] }
matrix-sdk-qrcode = { version = "0.11.1", optional = true }
wasm-bindgen-test = "0.3.37"

[build-dependencies]
vergen-gitcl = { version = "1.0.0", features = ["build"] }

[dependencies.matrix-sdk-crypto]
version = "0.11.1"
default-features = false
features = ["js", "automatic-room-key-forwarding"]
"#;
        let doc = super::update_cargo_toml(input).unwrap().unwrap();
        insta::assert_snapshot!(doc)
    }
}
