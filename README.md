# chksum-sha2-256

[![crates.io](https://img.shields.io/crates/v/chksum-sha2-256?style=flat-square&logo=rust "crates.io")](https://crates.io/crates/chksum-sha2-256)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/sha2-256/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/sha2-256/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-sha2-256?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-sha2-256/)
[![MSRV](https://img.shields.io/badge/MSRV-1.70.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/sha2-256/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-sha2-256/0.0.0/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-sha2-256/0.0.0)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/sha2-256?style=flat-square "LICENSE")](https://github.com/chksum-rs/sha2-256/blob/master/LICENSE)

An implementation of the SHA-2 256 hash function with a straightforward interface for computing digests of bytes, files, directories, and more.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-sha2-256 = "0.0.0"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-sha2-256
```

## Usage

Use the `chksum` function to calculate digest of file, directory and so on.

```rust
use chksum_sha2_256 as sha2_256;

let file = File::open(path)?;
let digest = sha2_256::chksum(file)?;
assert_eq!(
    digest.to_hex_lowercase(),
    "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-sha2-256/).

## License

This crate is licensed under the MIT License.
