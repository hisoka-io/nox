//! The persistent KPS identity and the addresses published for it.
//!
//! The certhash is the stable half of the node's KPS address
//! (`<ip>:<port>:<certhash>`) and is published on chain, so the key is created
//! exactly once (`nox-kps init`) and `nox-kps run` only ever loads it: a
//! silently regenerated key would change the published address. The private
//! key is never logged or printed; only the certhash is.

use std::net::IpAddr;
use std::path::Path;

use crate::error::IdentityError;

/// Creates the identity at `path` (`nox-kps init`): parent directory 0700,
/// key file 0600. Refuses to touch an existing file.
pub fn init(path: &Path) -> Result<kps::Identity, IdentityError> {
    if path.exists() {
        return Err(IdentityError::AlreadyExists {
            path: path.to_path_buf(),
        });
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            create_private_dir(parent)?;
        }
    }
    kps::Identity::load_or_create(path).map_err(|source| IdentityError::Create {
        path: path.to_path_buf(),
        source,
    })
}

/// Loads the existing identity for `nox-kps run`. The file must exist and be
/// readable by its owner only.
pub fn load(path: &Path) -> Result<kps::Identity, IdentityError> {
    match read_existing(path)? {
        None => Err(IdentityError::Missing {
            path: path.to_path_buf(),
        }),
        Some(identity) => {
            check_private(path)?;
            Ok(identity)
        }
    }
}

/// [`load`], then checks the certhash against `expected_certhash` (`run`).
pub fn load_expected(path: &Path, expected: Option<&str>) -> Result<kps::Identity, IdentityError> {
    let identity = load(path)?;
    match expected {
        None => Err(IdentityError::ExpectedCerthashMissing {
            path: path.to_path_buf(),
            actual: identity.certhash.clone(),
        }),
        Some(expected) if expected != identity.certhash => Err(IdentityError::CerthashMismatch {
            path: path.to_path_buf(),
            expected: expected.to_string(),
            actual: identity.certhash.clone(),
        }),
        Some(_) => Ok(identity),
    }
}

/// Reads an existing identity without creating one (`check-config`,
/// `address`). `Ok(None)` when the file does not exist.
pub fn read_existing(path: &Path) -> Result<Option<kps::Identity>, IdentityError> {
    let pem = match std::fs::read_to_string(path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(IdentityError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    kps::Identity::from_pem(&pem)
        .map(Some)
        .map_err(|source| IdentityError::Parse {
            path: path.to_path_buf(),
            source,
        })
}

/// Fails when group or other users can access the key file.
#[cfg(unix)]
pub fn check_private(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|source| IdentityError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode.trailing_zeros() >= 6 {
        Ok(())
    } else {
        Err(IdentityError::Permissions {
            path: path.to_path_buf(),
            mode,
        })
    }
}

#[cfg(not(unix))]
pub fn check_private(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|source| IdentityError::CreateDir {
            path: dir.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), IdentityError> {
    std::fs::create_dir_all(dir).map_err(|source| IdentityError::CreateDir {
        path: dir.to_path_buf(),
        source,
    })
}

/// Formats `ip:port:certhash`, bracketing IPv6 (KPS SPEC §2).
#[must_use]
pub fn format_address(ip: IpAddr, port: u16, certhash: &str) -> String {
    kps::format_address(&ip.to_string(), port, certhash)
}

/// The string published in the node's registry `metadataUrl` (§6):
/// `kps:<ip>:<port>:<certhash>/metadata.json`.
#[must_use]
pub fn metadata_url(address: &str) -> String {
    format!("kps:{address}/metadata.json")
}

/// Not reachable from the public internet: private, shared (CGNAT),
/// loopback, link-local or unique-local.
#[must_use]
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::pedantic
    )]

    use super::*;

    #[test]
    fn init_creates_once_and_load_returns_the_same_certhash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("kps.key");
        assert!(matches!(load(&path), Err(IdentityError::Missing { .. })));
        let created = init(&path).unwrap();
        assert!(created.certhash.starts_with("uEi"));
        for _ in 0..3 {
            assert_eq!(load(&path).unwrap().certhash, created.certhash);
        }
        let pem = std::fs::read(&path).unwrap();
        assert!(matches!(
            init(&path),
            Err(IdentityError::AlreadyExists { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), pem, "init never overwrites");
        assert_eq!(
            read_existing(&path).unwrap().unwrap().certhash,
            created.certhash
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_file_and_directory_are_private_and_loose_keys_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("id");
        let path = parent.join("kps.key");
        init(&path).unwrap();
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let Err(err) = load(&path) else {
            panic!("a 0644 key must be refused");
        };
        assert!(
            matches!(err, IdentityError::Permissions { mode: 0o644, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }

    #[test]
    fn run_requires_the_expected_certhash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kps.key");
        let id = init(&path).unwrap();
        assert!(matches!(
            load_expected(&path, None),
            Err(IdentityError::ExpectedCerthashMissing { .. })
        ));
        let other = kps::Identity::generate().unwrap();
        let Err(err) = load_expected(&path, Some(&other.certhash)) else {
            panic!("a foreign certhash must be refused");
        };
        assert!(err.to_string().contains(&id.certhash), "{err}");
        assert_eq!(
            load_expected(&path, Some(&id.certhash)).unwrap().certhash,
            id.certhash
        );
        assert!(crate::config::is_certhash(&id.certhash));
    }

    #[test]
    fn read_existing_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kps.key");
        assert!(read_existing(&path).unwrap().is_none());
        assert!(!path.exists());
        std::fs::write(&path, "not a pem").unwrap();
        assert!(matches!(
            read_existing(&path),
            Err(IdentityError::Parse { .. })
        ));
    }

    #[test]
    fn metadata_url_wraps_the_address() {
        assert_eq!(
            metadata_url("3.239.73.249:15005:uEiX"),
            "kps:3.239.73.249:15005:uEiX/metadata.json"
        );
    }

    #[test]
    fn addresses_bracket_ipv6() {
        assert_eq!(
            format_address("203.0.113.5".parse().unwrap(), 15005, "uEiX"),
            "203.0.113.5:15005:uEiX"
        );
        assert_eq!(
            format_address("2001:db8::7".parse().unwrap(), 15005, "uEiX"),
            "[2001:db8::7]:15005:uEiX"
        );
    }

    #[test]
    fn classifies_non_public_addresses() {
        for ip in [
            "10.1.2.3",
            "172.31.66.207",
            "192.168.1.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_non_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "3.236.170.102",
            "203.0.113.5",
            "2600:1f18::1",
            "100.128.0.1",
        ] {
            assert!(!is_non_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
