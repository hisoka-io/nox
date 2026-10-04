//! Hash-addressed worker bundles for the anon-rpc `kps:` resolver profile
//! (anon-rpc SPEC §4.1–4.2): `GET /keccak/<hh>/<62 hex>` answers `200` with
//! bytes whose keccak-256 equals the path, or `404`.
//!
//! Files are read, hashed and held in memory at scan time, so a request never
//! touches the disk and a file changed on disk after verification can never be
//! served. Names are content hashes, so a verified entry stays valid while its
//! file exists; a rescan only reads files with new names and drops entries
//! whose file is gone (deleting the file unpublishes the bundle).

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::header::{self, HeaderMap};
use sha3::{Digest, Keccak256};
use tracing::{info, warn};

use crate::config::BundleSettings;
use crate::error::BundleError;

/// `Cache-Control` for immutable, hash-addressed objects (anon-rpc network
/// guide; tor-js-gateway PROTOCOL §5).
pub const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// Media type of a worker bundle.
pub const BUNDLE_CONTENT_TYPE: &str = "text/javascript";

/// One verified bundle.
#[derive(Debug)]
pub struct Bundle {
    /// The exact bytes whose keccak-256 is the bundle's name.
    pub identity: Bytes,
    /// A gzip encoding of `identity`, kept only when it is smaller.
    pub gzip: Option<Bytes>,
}

/// What a scan found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub loaded: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Files whose bytes do not hash to their name.
    pub mismatched: Vec<PathBuf>,
    /// Files over `bundles.max_bundle_bytes`, or beyond `bundles.max_bundles`.
    pub skipped: Vec<PathBuf>,
    /// Entries that are not bundle names (README, licence, …).
    pub ignored: usize,
}

type Index = HashMap<[u8; 32], Arc<Bundle>>;

/// The in-memory bundle index.
#[derive(Debug)]
pub struct BundleStore {
    settings: BundleSettings,
    index: RwLock<Arc<Index>>,
}

impl BundleStore {
    /// Scans `settings.dir` once. The directory must exist.
    pub fn load(settings: BundleSettings) -> Result<(Self, ScanReport), BundleError> {
        let (index, report) = scan(&settings, &Index::new())?;
        Ok((
            Self {
                settings,
                index: RwLock::new(Arc::new(index)),
            },
            report,
        ))
    }

    /// Rescans the directory. On a read error the current index stays in
    /// place: a failed refresh never reduces what is served.
    pub fn rescan(&self) -> Result<ScanReport, BundleError> {
        let current = self.snapshot();
        let (index, report) = scan(&self.settings, &current)?;
        *self.index.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(index);
        Ok(report)
    }

    /// The bundle named by `hash`, if loaded.
    #[must_use]
    pub fn get(&self, hash: &[u8; 32]) -> Option<Arc<Bundle>> {
        self.snapshot().get(hash).cloned()
    }

    /// Number of bundles loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Hex names of the loaded bundles, sorted.
    #[must_use]
    pub fn hashes(&self) -> Vec<String> {
        let mut v: Vec<String> = self.snapshot().keys().map(hex::encode).collect();
        v.sort();
        v
    }

    #[must_use]
    pub fn settings(&self) -> &BundleSettings {
        &self.settings
    }

    fn snapshot(&self) -> Arc<Index> {
        Arc::clone(&self.index.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Logs a scan report at the right levels. Hashes are public (they are on
/// chain), file paths are operator-local.
pub fn log_report(report: &ScanReport, dir: &Path) {
    for hash in &report.added {
        info!(bundle = %hash, "worker bundle loaded");
    }
    for hash in &report.removed {
        info!(bundle = %hash, "worker bundle removed (file deleted)");
    }
    for path in &report.mismatched {
        warn!(file = %path.display(), "worker bundle refused: keccak-256 of the bytes does not match the file name");
    }
    for path in &report.skipped {
        warn!(file = %path.display(), "worker bundle skipped: over bundles.max_bundle_bytes or bundles.max_bundles");
    }
    if !report.added.is_empty() || !report.removed.is_empty() {
        info!(dir = %dir.display(), loaded = report.loaded, "worker bundle index updated");
    }
}

/// keccak-256 as lowercase hex (the Ethereum hash, not SHA3-256).
#[must_use]
pub fn keccak256_hex(bytes: &[u8]) -> String {
    hex::encode(Keccak256::digest(bytes))
}

/// `s` is exactly `len` lowercase hex digits.
#[must_use]
pub fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parses the part of a `/keccak/<hh>/<rest>` path after the prefix.
#[must_use]
pub fn parse_bundle_path(rest: &str) -> Option<[u8; 32]> {
    let (hh, tail) = rest.split_once('/')?;
    if !is_lower_hex(hh, 2) || !is_lower_hex(tail, 62) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(format!("{hh}{tail}"), &mut out).ok()?;
    Some(out)
}

/// The client listed `gzip` with a non-zero quality in `Accept-Encoding`.
/// Only an explicit `gzip` counts: SPEC §4.2 allows a coding the request
/// advertised, and a wildcard does not name one.
#[must_use]
pub fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|item| {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or("").trim();
            if !coding.eq_ignore_ascii_case("gzip") {
                return false;
            }
            let quality = parts
                .find_map(|p| {
                    let (k, v) = p.split_once('=')?;
                    k.trim()
                        .eq_ignore_ascii_case("q")
                        .then(|| v.trim().parse::<f32>().ok())?
                })
                .unwrap_or(1.0);
            quality > 0.0
        })
}

fn scan(settings: &BundleSettings, previous: &Index) -> Result<(Index, ScanReport), BundleError> {
    let dir = &settings.dir;
    let mut report = ScanReport::default();
    // name -> path, in hash order so `max_bundles` truncation is deterministic.
    let mut found: Vec<([u8; 32], PathBuf)> = Vec::new();
    let mut seen = BTreeSet::new();

    let entries = std::fs::read_dir(dir).map_err(|source| BundleError::ReadDir {
        path: dir.clone(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| BundleError::ReadDir {
            path: dir.clone(),
            source,
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            report.ignored += 1;
            continue;
        };
        let path = entry.path();
        let is_dir = path.is_dir();
        if !is_dir && is_lower_hex(name, 64) {
            if let Some(hash) = decode_hash(name) {
                if seen.insert(hash) {
                    found.push((hash, path));
                }
            }
        } else if is_dir && is_lower_hex(name, 2) {
            let shard = std::fs::read_dir(&path).map_err(|source| BundleError::ReadDir {
                path: path.clone(),
                source,
            })?;
            for item in shard {
                let item = item.map_err(|source| BundleError::ReadDir {
                    path: path.clone(),
                    source,
                })?;
                let file_name = item.file_name();
                match file_name.to_str() {
                    Some(rest) if is_lower_hex(rest, 62) && !item.path().is_dir() => {
                        if let Some(hash) = decode_hash(&format!("{name}{rest}")) {
                            if seen.insert(hash) {
                                found.push((hash, item.path()));
                            }
                        }
                    }
                    _ => report.ignored += 1,
                }
            }
        } else {
            report.ignored += 1;
        }
    }
    found.sort_by_key(|(hash, _)| *hash);

    let mut index = Index::new();
    for (hash, path) in found {
        if index.len() >= settings.max_bundles {
            report.skipped.push(path);
            continue;
        }
        if let Some(existing) = previous.get(&hash) {
            index.insert(hash, Arc::clone(existing));
            continue;
        }
        let size = match std::fs::metadata(&path) {
            Ok(meta) => meta.len(),
            Err(e) => {
                warn!(file = %path.display(), error = %e, "worker bundle unreadable; skipped");
                report.skipped.push(path);
                continue;
            }
        };
        if size > settings.max_bundle_bytes as u64 {
            report.skipped.push(path);
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!(file = %path.display(), error = %e, "worker bundle unreadable; skipped");
                report.skipped.push(path);
                continue;
            }
        };
        if bytes.len() > settings.max_bundle_bytes {
            report.skipped.push(path);
            continue;
        }
        let digest: [u8; 32] = Keccak256::digest(&bytes).into();
        if digest != hash {
            report.mismatched.push(path);
            continue;
        }
        let gzip = if settings.gzip {
            let compressed = gzip(&bytes).map_err(|source| BundleError::Compress {
                hash: hex::encode(hash),
                source,
            })?;
            (compressed.len() < bytes.len()).then(|| Bytes::from(compressed))
        } else {
            None
        };
        index.insert(
            hash,
            Arc::new(Bundle {
                identity: Bytes::from(bytes),
                gzip,
            }),
        );
        report.added.push(hex::encode(hash));
    }
    report.removed = previous
        .keys()
        .filter(|h| !index.contains_key(*h))
        .map(hex::encode)
        .collect();
    report.removed.sort();
    report.added.sort();
    report.loaded = index.len();
    Ok((index, report))
}

fn decode_hash(hex64: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex64, &mut out).ok()?;
    Some(out)
}

fn gzip(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::with_capacity(bytes.len() / 2), Compression::best());
    enc.write_all(bytes)?;
    enc.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::io::Read;

    use http::HeaderValue;

    use super::*;

    fn settings(dir: &Path) -> BundleSettings {
        BundleSettings {
            dir: dir.to_path_buf(),
            max_bundle_bytes: 1024 * 1024,
            max_bundles: 16,
            rescan_interval: None,
            gzip: true,
        }
    }

    fn write_sharded(dir: &Path, bytes: &[u8]) -> String {
        let hash = keccak256_hex(bytes);
        std::fs::create_dir_all(dir.join(&hash[..2])).unwrap();
        std::fs::write(dir.join(&hash[..2]).join(&hash[2..]), bytes).unwrap();
        hash
    }

    fn arr(hash: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(hash, &mut out).unwrap();
        out
    }

    #[test]
    fn keccak_is_the_ethereum_hash() {
        assert_eq!(
            keccak256_hex(b""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn loads_sharded_and_flat_files_and_ignores_others() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_sharded(dir.path(), b"bundle a");
        let b_bytes = b"bundle b".repeat(100);
        let b = keccak256_hex(&b_bytes);
        std::fs::write(dir.path().join(&b), &b_bytes).unwrap();
        std::fs::write(dir.path().join("README.md"), "hi").unwrap();
        std::fs::write(dir.path().join(format!("{}.js", keccak256_hex(b"x"))), "x").unwrap();
        let (store, report) = BundleStore::load(settings(dir.path())).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(report.ignored, 2);
        assert_eq!(&*store.get(&arr(&a)).unwrap().identity, b"bundle a");
        let bundle_b = store.get(&arr(&b)).unwrap();
        assert_eq!(&*bundle_b.identity, b_bytes.as_slice());
        let gz = bundle_b.gzip.as_ref().expect("repetitive bytes compress");
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b_bytes);
        assert!(
            store.get(&arr(&a)).unwrap().gzip.is_none(),
            "8 bytes do not compress"
        );
    }

    #[test]
    fn refuses_files_whose_bytes_do_not_match_their_name() {
        let dir = tempfile::tempdir().unwrap();
        let hash = keccak256_hex(b"genuine");
        std::fs::create_dir_all(dir.path().join(&hash[..2])).unwrap();
        std::fs::write(dir.path().join(&hash[..2]).join(&hash[2..]), b"tampered").unwrap();
        let (store, report) = BundleStore::load(settings(dir.path())).unwrap();
        assert!(store.is_empty());
        assert_eq!(report.mismatched.len(), 1);
    }

    #[test]
    fn enforces_size_and_count_caps() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = settings(dir.path());
        s.max_bundle_bytes = 10;
        s.max_bundles = 1;
        write_sharded(dir.path(), b"small");
        write_sharded(dir.path(), b"also small");
        write_sharded(dir.path(), b"this one is far too large");
        let (store, report) = BundleStore::load(s).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(report.skipped.len(), 2);
    }

    #[test]
    fn rescan_adds_new_and_drops_deleted_files() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_sharded(dir.path(), b"first");
        let (store, _) = BundleStore::load(settings(dir.path())).unwrap();
        let b = write_sharded(dir.path(), b"second");
        std::fs::remove_file(dir.path().join(&a[..2]).join(&a[2..])).unwrap();
        let report = store.rescan().unwrap();
        assert_eq!(report.added, vec![b.clone()]);
        assert_eq!(report.removed, vec![a.clone()]);
        assert!(store.get(&arr(&a)).is_none());
        assert!(store.get(&arr(&b)).is_some());
        assert_eq!(store.hashes(), vec![b]);
    }

    #[test]
    fn rescan_keeps_verified_bytes_when_a_file_changes_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let a = write_sharded(dir.path(), b"original");
        let (store, _) = BundleStore::load(settings(dir.path())).unwrap();
        std::fs::write(dir.path().join(&a[..2]).join(&a[2..]), b"swapped!").unwrap();
        store.rescan().unwrap();
        assert_eq!(&*store.get(&arr(&a)).unwrap().identity, b"original");
    }

    #[test]
    fn a_failed_rescan_keeps_serving() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("bundles");
        std::fs::create_dir_all(&root).unwrap();
        let a = write_sharded(&root, b"keep me");
        let (store, _) = BundleStore::load(settings(&root)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(store.rescan().is_err());
        assert!(store.get(&arr(&a)).is_some());
    }

    #[test]
    fn missing_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = BundleStore::load(settings(&dir.path().join("absent"))).unwrap_err();
        assert!(err.to_string().contains("absent"), "{err}");
    }

    #[test]
    fn bundle_paths_must_be_lowercase_split_hex() {
        let h = keccak256_hex(b"p");
        assert!(parse_bundle_path(&format!("{}/{}", &h[..2], &h[2..])).is_some());
        assert!(parse_bundle_path(&h).is_none());
        assert!(parse_bundle_path(&format!("AB/{}", &h[2..])).is_none());
        assert!(
            parse_bundle_path(&format!("ab/{}", h[2..].to_uppercase())).is_none()
                || h[2..].bytes().all(|b| b.is_ascii_digit())
        );
        assert!(parse_bundle_path(&format!("{}/{}x", &h[..2], &h[2..63])).is_none());
        assert!(parse_bundle_path(&format!("{}/{}/", &h[..2], &h[2..])).is_none());
        assert!(parse_bundle_path("../etc/passwd").is_none());
    }

    #[test]
    fn gzip_only_when_explicitly_accepted() {
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::ACCEPT_ENCODING, HeaderValue::from_str(v).unwrap());
            accepts_gzip(&h)
        };
        assert!(with("gzip"));
        assert!(with("zstd, br, gzip, deflate"));
        assert!(with("GZIP;q=0.5"));
        assert!(!with("gzip;q=0"));
        assert!(!with("deflate"));
        assert!(!with("*"));
        assert!(!with("x-gzip"));
        assert!(!accepts_gzip(&HeaderMap::new()));
    }
}
