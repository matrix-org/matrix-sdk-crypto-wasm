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

    update_cargo_toml()?;
    cargo_update()?;
    Ok(())
}

/// Update the `matrix-rust-sdk` entries in `Cargo.toml`, so that they use a
/// `git` uri, with no `version` or `rev`, meaning that we will pull the latest
/// version from git.
fn update_cargo_toml() -> Result<()> {
    let cargo_toml = "Cargo.toml";

    let mut doc: DocumentMut = fs::read_to_string(cargo_toml)?.parse()?;

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
        fs::write(cargo_toml, doc.to_string())?;
    }
    Ok(())
}

fn cargo_update() -> Result<()> {
    let sh = Shell::new()?;
    cmd!(sh, "cargo update").run()?;
    Ok(())
}
