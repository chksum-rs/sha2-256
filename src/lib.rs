//! This crate provides an implementation of the SHA-2 256 hash function with a straightforward interface for computing digests of bytes, files, directories, and more.
//!
//! For a low-level interface, you can explore the [`chksum_hash_sha2_256`] crate.
//!
//! # Setup
//!
//! To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2-256 = "0.0.0"
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```sh
//! cargo add chksum-sha2-256
//! ```     
//!
//! # Usage
//!
//! Use the [`chksum`] function to calculate digest of file, directory and so on.
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_256::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Asynchronous Runtime
//!
//! Use the [`async_chksum`] function to calculate digest of file, directory and so on.
//!
//! ```rust
//! # #[cfg(feature = "async-runtime-tokio")]
//! # {
//! # use std::path::Path;
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//! use tokio::fs::File;
//!
//! # async fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path).await?;
//! let digest = sha2_256::async_chksum(file).await?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! # Input Types
//!
//! ## Bytes
//!
//! ### Array
//!
//! ```rust
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = [0, 1, 2, 3];
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### Vec
//!
//! ```rust
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = vec![0, 1, 2, 3];
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### Slice
//!
//! ```rust
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = &[0, 1, 2, 3];
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Strings
//!
//! ### str
//!
//! ```rust
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = "&str";
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### String
//!
//! ```rust
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = String::from("String");
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## File
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_256::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Directory
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::read_dir;
//!
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let readdir = read_dir(path)?;
//! let digest = sha2_256::chksum(readdir)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Path
//!
//! ```rust
//! # use std::path::Path;
//! use std::path::PathBuf;
//!
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let path = PathBuf::from(path);
//! let digest = sha2_256::chksum(path)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Standard Input
//!
//! ```rust
//! use std::io::stdin;
//!
//! # use chksum_sha2_256::Result;
//! use chksum_sha2_256 as sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let stdin = stdin();
//! let digest = sha2_256::chksum(stdin)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! Cargo features are utilized to enable extra options.
//!
//! * `reader` enables the [`reader`] module with the [`Reader`] struct.
//! * `writer` enables the [`writer`] module with the [`Writer`] struct.
//!
//! By default, neither of these features is enabled.
//!
//! To customize your setup, disable the default features and enable only those that you need in your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2-256 = { version = "0.0.0", features = ["reader", "writer"] }
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```shell
//! cargo add chksum-sha2-256 --features reader,writer
//! ```
//!
//! ## Asynchronous Runtime
//!
//! * `async-runtime-tokio`: Enables async interface for Tokio runtime.
//!
//! By default, neither of these features is enabled.
//!
//! # License
//!
//! This crate is licensed under the MIT License.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]

#[cfg(feature = "reader")]
pub mod reader;
#[cfg(feature = "writer")]
pub mod writer;

use std::fmt::{self, Display, Formatter, LowerHex, UpperHex};

use chksum_core as core;
#[cfg(feature = "async-runtime-tokio")]
#[doc(no_inline)]
pub use chksum_core::AsyncChksumable;
#[doc(no_inline)]
pub use chksum_core::{Chksumable, Error, Hash, Hashable, Result};
#[doc(no_inline)]
pub use chksum_hash_sha2_256 as hash;

#[cfg(all(feature = "reader", feature = "async-runtime-tokio"))]
#[doc(inline)]
pub use crate::reader::AsyncReader;
#[cfg(feature = "reader")]
#[doc(inline)]
pub use crate::reader::Reader;
#[cfg(all(feature = "writer", feature = "async-runtime-tokio"))]
#[doc(inline)]
pub use crate::writer::AsyncWriter;
#[cfg(feature = "writer")]
#[doc(inline)]
pub use crate::writer::Writer;

/// Creates a new hash.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_256 as sha2_256;
///
/// let mut hash = sha2_256::new();
/// hash.update(b"example data");
/// let digest = hash.digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
/// );
/// ```
#[must_use]
pub fn new() -> SHA2_256 {
    SHA2_256::new()
}

/// Creates a default hash.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_256 as sha2_256;
///
/// let mut hash = sha2_256::default();
/// hash.update(b"example data");
/// let digest = hash.digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
/// );
/// ```
#[must_use]
pub fn default() -> SHA2_256 {
    core::default()
}

/// Computes the hash of the given input.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_256 as sha2_256;
///
/// let data = b"example data";
/// let digest = sha2_256::hash(data);
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
/// );
/// ```
pub fn hash(data: impl core::Hashable) -> Digest {
    core::hash::<SHA2_256>(data)
}

/// Computes the hash of the given input.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_256 as sha2_256;
///
/// let data = b"example data";
/// if let Ok(digest) = sha2_256::chksum(data) {
///     assert_eq!(
///         digest.to_hex_lowercase(),
///         "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
///     );
/// }
/// ```
pub fn chksum(data: impl core::Chksumable) -> Result<Digest> {
    core::chksum::<SHA2_256>(data)
}

/// Computes the hash of the given input.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_256 as sha2_256;
///
/// # async fn wrapper() {
/// let data = b"example data";
/// if let Ok(digest) = sha2_256::async_chksum(data).await {
///     assert_eq!(
///         digest.to_hex_lowercase(),
///         "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
///     );
/// }
/// # }
/// ```
#[cfg(feature = "async-runtime-tokio")]
pub async fn async_chksum(data: impl core::AsyncChksumable) -> Result<Digest> {
    core::async_chksum::<SHA2_256>(data).await
}

/// The SHA-2 256 hash instance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SHA2_256 {
    inner: hash::Update,
}

impl SHA2_256 {
    /// Calculates the hash digest of an input data.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_256::SHA2_256;
    ///
    /// let data = b"example data";
    /// let digest = SHA2_256::hash(data);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
    /// );
    /// ```
    #[must_use]
    pub fn hash<T>(data: T) -> Digest
    where
        T: AsRef<[u8]>,
    {
        let mut hash = Self::new();
        hash.update(data);
        hash.digest()
    }

    /// Creates a new hash.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_256::SHA2_256;
    ///
    /// let mut hash = SHA2_256::new();
    /// hash.update(b"example data");
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
    /// );
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let inner = hash::Update::new();
        Self { inner }
    }

    /// Updates the hash state with an input data.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_256::SHA2_256;
    ///
    /// let mut hash = SHA2_256::new();
    /// hash.update(b"example");
    /// hash.update(" ");
    /// hash.update("data");
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
    /// );
    /// ```
    pub fn update<T>(&mut self, data: T)
    where
        T: AsRef<[u8]>,
    {
        self.inner.update(data);
    }

    /// Resets the hash state to its initial state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_256::SHA2_256;
    ///
    /// let mut hash = SHA2_256::new();
    /// hash.update(b"example data");
    /// hash.reset();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    /// );
    /// ```
    pub fn reset(&mut self) {
        self.inner.reset();
    }

    /// Produces the hash digest.
    ///
    /// # Example
    ///
    /// ```
    /// use chksum_sha2_256::SHA2_256;
    ///
    /// let mut hash = SHA2_256::new();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    /// );
    /// ```
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.inner.digest().into()
    }
}

impl core::Hash for SHA2_256 {
    type Digest = Digest;

    fn update<T>(&mut self, data: T)
    where
        T: AsRef<[u8]>,
    {
        self.update(data);
    }

    fn reset(&mut self) {
        self.reset();
    }

    fn digest(&self) -> Self::Digest {
        self.digest()
    }
}

/// A hash digest.
pub struct Digest(hash::Digest);

impl Digest {
    /// Creates a new digest.
    #[must_use]
    pub const fn new(digest: [u8; hash::DIGEST_LENGTH_BYTES]) -> Self {
        let inner = hash::Digest::new(digest);
        Self(inner)
    }

    /// Returns a byte slice of the digest's contents.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        let Self(inner) = self;
        inner.as_bytes()
    }

    /// Consumes the digest, returning the digest bytes.
    #[must_use]
    pub fn into_inner(self) -> [u8; hash::DIGEST_LENGTH_BYTES] {
        let Self(inner) = self;
        inner.into_inner()
    }

    /// Returns a string in the lowercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_256 as sha2_256;
    ///
    /// #[rustfmt::skip]
    /// let digest = [
    ///     0xE3, 0xB0, 0xC4, 0x42,
    ///     0x98, 0xFC, 0x1C, 0x14,
    ///     0x9A, 0xFB, 0xF4, 0xC8,
    ///     0x99, 0x6F, 0xB9, 0x24,
    ///     0x27, 0xAE, 0x41, 0xE4,
    ///     0x64, 0x9B, 0x93, 0x4C,
    ///     0xA4, 0x95, 0x99, 0x1B,
    ///     0x78, 0x52, 0xB8, 0x55,
    /// ];
    /// let digest = sha2_256::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_lowercase(&self) -> String {
        let Self(inner) = self;
        inner.to_hex_lowercase()
    }

    /// Returns a string in the uppercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_256 as sha2_256;
    ///
    /// #[rustfmt::skip]
    /// let digest = [
    ///     0xE3, 0xB0, 0xC4, 0x42,
    ///     0x98, 0xFC, 0x1C, 0x14,
    ///     0x9A, 0xFB, 0xF4, 0xC8,
    ///     0x99, 0x6F, 0xB9, 0x24,
    ///     0x27, 0xAE, 0x41, 0xE4,
    ///     0x64, 0x9B, 0x93, 0x4C,
    ///     0xA4, 0x95, 0x99, 0x1B,
    ///     0x78, 0x52, 0xB8, 0x55,
    /// ];
    /// let digest = sha2_256::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_uppercase(),
    ///     "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_uppercase(&self) -> String {
        let Self(inner) = self;
        inner.to_hex_uppercase()
    }
}

impl core::Digest for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        let Self(inner) = self;
        inner.as_bytes()
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(inner) = self;
        Display::fmt(inner, f)
    }
}

impl LowerHex for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(inner) = self;
        LowerHex::fmt(inner, f)
    }
}

impl UpperHex for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(inner) = self;
        UpperHex::fmt(inner, f)
    }
}

impl From<[u8; hash::DIGEST_LENGTH_BYTES]> for Digest {
    fn from(digest: [u8; hash::DIGEST_LENGTH_BYTES]) -> Self {
        Self::new(digest)
    }
}

impl From<hash::Digest> for Digest {
    fn from(digest: hash::Digest) -> Self {
        Self(digest)
    }
}
