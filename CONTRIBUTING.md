# Contributing

## Build

You need Rust 1.89 or later from [rustup](https://rustup.rs) and the Xcode Command Line Tools (`xcode-select --install`). The FIDO2 crate compiles C code, and packaging uses `codesign`, `pkgbuild`, and `productbuild`.

```sh
git clone https://github.com/BJMCox/fido2lock.git
cd fido2lock
cargo test
cargo build --release               # target/release/fido2lock, under 1 MiB
cargo run -- enroll-key --label test    # terminal commands during development
cargo run --release                     # the menu-bar app during development
```

When the app runs unbundled, "Start at Login" does not work.

## Signing identity

```sh
cargo xtask cert
```

This creates a self-signed code-signing certificate, `fido2lock local signing`, in your login keychain once per build Mac. It asks for your password to trust the certificate. A second run does nothing. Check it with `security find-identity -v -p codesigning`, and remove it with `security delete-identity -c "fido2lock local signing"`. Every build signed with it has the same designated requirement, so macOS keeps the Start at Login approval across upgrades. Build local packages on one Mac, so they all carry the same identity.

## App, package, and disk image

```sh
cargo xtask bundle     # target/bundle/fido2lock.app, signed
cargo xtask package    # dist/fido2lock-<version>.pkg
cargo xtask dmg        # dist/fido2lock-<version>.dmg, about 0.5 MB, LZMA
cargo xtask icon       # only after editing assets/*.svg; needs rsvg-convert (brew install librsvg)
```

The disk image window layout lives in `assets/dmg/DS_Store`. After changing its background or icon positions, run `cargo xtask dmg-layout`, which lays out the window with Finder and saves the file. Terminal asks once for permission to control Finder.

`codesign -d -r- target/bundle/fido2lock.app` should show `certificate leaf` in the designated requirement. A `cdhash` means the identity is missing. The version comes from `[workspace.package]` in `Cargo.toml`. The package installs only `/Applications/fido2lock.app`, with no settings or scripts. Install a local package with `sudo installer -pkg dist/fido2lock-<version>.pkg -target /`.

## Run CodeQL locally

`cargo xtask codeql` runs the same analysis as the `codeql` workflow, with the shared config in `.github/codeql`, and fails on any finding. Run it before pushing. It needs the full CodeQL bundle, the CLI with every query pack, which GitHub's workflow uses too:

```sh
gh release download codeql-bundle-v2.27.1 -R github/codeql-action -p 'codeql-bundle-osx64.tar.zst*'
shasum -a 256 -c codeql-bundle-osx64.tar.zst.checksum.txt
mkdir -p ~/.codeql/bundle && tar -xf codeql-bundle-osx64.tar.zst -C ~/.codeql/bundle
ln -s ~/.codeql/bundle/codeql/codeql ~/.local/bin/codeql
cargo xtask codeql
```

A run takes about three minutes. Reports and databases stay in `~/Library/Caches/fido2lock/codeql`. Tests live in `tests.rs` files, which the config excludes because CodeQL does not recognize `#[cfg(test)]`.

## Release

1. Raise `version` under `[workspace.package]` in `Cargo.toml`, commit, and push to `main`.
2. Run `cargo xtask release`. It checks that the tree is clean, `main` matches `origin/main`, and tag `v<version>` is new, then runs the tests and pushes the tag.
3. Approve the `release` environment in GitHub Actions.

The release workflow builds the tag on a GitHub-hosted runner through the reusable workflow `.github/workflows/build.yml`. It tests, signs, and builds the `.dmg` and `.pkg`, and creates their signed provenance. The signing identity sits in the `release` environment, which only `v*` tags can use, and only after approval.

After the release is published, a job uploads the installers to VirusTotal and links each scan in the release notes. Its API key sits in the `virustotal` environment, which only `v*` tags can use and which needs no approval. To set it up, create the environment with a `v*` tag rule, then run `gh secret set VT_API_KEY --env virustotal` with the key from your VirusTotal account.
