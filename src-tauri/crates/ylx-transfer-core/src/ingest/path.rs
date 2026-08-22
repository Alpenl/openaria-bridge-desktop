//! Portable path validation and no-link filesystem checks for untrusted media.

use std::fmt;
use std::fs::{self, File};
use std::io;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CLOCK$",
    "CONIN$", "CONOUT$",
];

/// A validated, portable relative path. It can never be absolute, contain a
/// parent component, use a backslash as an alternate separator, or name a
/// Windows device/alternate stream.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafeRelativePath(String);

impl SafeRelativePath {
    pub fn parse(value: impl Into<String>) -> Result<Self, PathSafetyError> {
        let value = value.into();
        validate_relative_path(&value, 32, 1_024)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    #[must_use]
    pub fn join_to(&self, root: &Path) -> PathBuf {
        self.components()
            .fold(root.to_path_buf(), |path, component| path.join(component))
    }
}

impl fmt::Debug for SafeRelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SafeRelativePath")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for SafeRelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for SafeRelativePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SafeRelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathSafetyError {
    #[error("relative path must not be empty")]
    Empty,
    #[error("path is longer than the configured {maximum}-byte limit")]
    TooLong { maximum: usize },
    #[error("path has more than the configured {maximum} components")]
    TooDeep { maximum: usize },
    #[error("absolute paths and platform prefixes are forbidden")]
    AbsoluteOrPrefixed,
    #[error("empty, current-directory, and parent-directory components are forbidden")]
    DotOrEmptyComponent,
    #[error("backslash path separators are forbidden")]
    Backslash,
    #[error("path component {component:?} contains a NUL/control/forbidden character")]
    ForbiddenCharacter { component: String },
    #[error("path component {component:?} contains a Windows drive or alternate stream marker")]
    DriveOrAlternateStream { component: String },
    #[error("path component {component:?} is a Windows-reserved device name")]
    ReservedDeviceName { component: String },
    #[error("path component {component:?} has a trailing dot or space")]
    TrailingDotOrSpace { component: String },
    #[error("filesystem root is not a directory")]
    RootNotDirectory,
    #[error("filesystem entry is a symbolic link, junction, or reparse point: {path}")]
    LinkNotAllowed { path: PathBuf },
    #[error("filesystem entry is not a directory: {path}")]
    NotDirectory { path: PathBuf },
    #[error("filesystem entry is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("filesystem entry has unexpected hard links: {path}")]
    UnexpectedHardlink { path: PathBuf },
    #[error("filesystem entry changed while it was open: {path}")]
    ChangedWhileOpen { path: PathBuf },
    #[error("filesystem entry cannot be inspected at {path}: {message}")]
    Inspection {
        path: PathBuf,
        kind: io::ErrorKind,
        message: String,
    },
}

/// Validate a manifest path without touching the filesystem.
pub fn validate_relative_path(
    value: &str,
    maximum_components: usize,
    maximum_bytes: usize,
) -> Result<(), PathSafetyError> {
    if value.is_empty() {
        return Err(PathSafetyError::Empty);
    }
    if value.len() > maximum_bytes {
        return Err(PathSafetyError::TooLong {
            maximum: maximum_bytes,
        });
    }
    if value.contains('\\') {
        return Err(PathSafetyError::Backslash);
    }
    if Path::new(value).is_absolute()
        || Path::new(value)
            .components()
            .any(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
    {
        return Err(PathSafetyError::AbsoluteOrPrefixed);
    }

    let components: Vec<&str> = value.split('/').collect();
    if components.len() > maximum_components {
        return Err(PathSafetyError::TooDeep {
            maximum: maximum_components,
        });
    }
    for component in components {
        validate_component(component)?;
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<(), PathSafetyError> {
    if component.is_empty() || component == "." || component == ".." {
        return Err(PathSafetyError::DotOrEmptyComponent);
    }
    if component.contains(':') {
        return Err(PathSafetyError::DriveOrAlternateStream {
            component: component.to_string(),
        });
    }
    if component.chars().any(|character| {
        character == '\0'
            || character.is_control()
            || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
    }) {
        return Err(PathSafetyError::ForbiddenCharacter {
            component: component.to_string(),
        });
    }
    if component.ends_with('.') || component.ends_with(' ') {
        return Err(PathSafetyError::TrailingDotOrSpace {
            component: component.to_string(),
        });
    }
    let upper = component.to_ascii_uppercase();
    let base = upper.split('.').next().unwrap_or(&upper);
    if WINDOWS_RESERVED_NAMES.contains(&base) {
        return Err(PathSafetyError::ReservedDeviceName {
            component: component.to_string(),
        });
    }
    Ok(())
}

/// Resolve an already validated candidate directory while rejecting links at
/// every component. This deliberately uses `symlink_metadata`, never
/// `metadata`, so the safety check itself does not follow a link.
pub fn resolve_directory_no_links(
    root: &Path,
    relative: &SafeRelativePath,
) -> Result<PathBuf, PathSafetyError> {
    inspect_root(root)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let metadata = inspect_entry(&current)?;
        if !metadata.is_dir() {
            return Err(PathSafetyError::NotDirectory { path: current });
        }
    }
    Ok(current)
}

/// Resolve an already validated file path while rejecting links and special
/// files at every component. The mounted adapter must still open with the
/// platform's no-follow/reparse-safe flags to close the check/open race.
pub fn resolve_regular_file_no_links(
    root: &Path,
    relative: &SafeRelativePath,
) -> Result<PathBuf, PathSafetyError> {
    inspect_root(root)?;
    let mut current = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        current.push(component);
        let metadata = inspect_entry(&current)?;
        if components.peek().is_some() {
            if !metadata.is_dir() {
                return Err(PathSafetyError::NotDirectory { path: current });
            }
        } else if !metadata.is_file() {
            return Err(PathSafetyError::NotRegularFile { path: current });
        }
    }
    Ok(current)
}

#[derive(Debug)]
pub struct OpenedRegularFile {
    file: File,
    identity: FileIdentity,
    display_path: PathBuf,
}

impl OpenedRegularFile {
    #[must_use]
    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.identity.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn recheck(&self) -> Result<(), PathSafetyError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|error| inspection_error(self.display_path.clone(), error))?;
        let observed = FileIdentity::from_open_metadata(&metadata, &self.display_path)?;
        if observed != self.identity {
            return Err(PathSafetyError::ChangedWhileOpen {
                path: self.display_path.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(unix)]
    hardlinks: u64,
}

impl FileIdentity {
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn from_open_metadata(
        metadata: &fs::Metadata,
        display_path: &Path,
    ) -> Result<Self, PathSafetyError> {
        if !metadata.is_file() {
            return Err(PathSafetyError::NotRegularFile {
                path: display_path.to_path_buf(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if metadata.nlink() != 1 {
                return Err(PathSafetyError::UnexpectedHardlink {
                    path: display_path.to_path_buf(),
                });
            }
            Ok(Self {
                len: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
                hardlinks: metadata.nlink(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                len: metadata.len(),
            })
        }
    }
}

/// Open an already-validated relative regular file beneath `root` without
/// following links at any component.  On Unix this is descriptor-rooted:
/// parents are opened with `openat(..., O_DIRECTORY|O_NOFOLLOW)` and the leaf
/// with `O_NOFOLLOW`; the returned file carries an `fstat` identity that must
/// be rechecked after bounded reads.
#[cfg(unix)]
pub fn open_regular_file_beneath(
    root: &Path,
    relative: &SafeRelativePath,
) -> Result<OpenedRegularFile, PathSafetyError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let display_path = relative.join_to(root);
    let root_name = CString::new(root.as_os_str().as_bytes()).map_err(|_| {
        PathSafetyError::ForbiddenCharacter {
            component: root.display().to_string(),
        }
    })?;
    let root_fd = open_path_descriptor(
        root_name.as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )
    .map_err(|error| inspection_error(root.to_path_buf(), error))?;
    let mut current = root_fd;
    let mut current_path = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let name = CString::new(component.as_bytes()).map_err(|_| {
            PathSafetyError::ForbiddenCharacter {
                component: component.to_string(),
            }
        })?;
        current_path.push(component);
        let flags = if components.peek().is_some() {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        } else {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        let next = open_at_descriptor(&current, name.as_ptr(), flags)
            .map_err(|error| inspection_error(current_path.clone(), error))?;
        if components.peek().is_some() {
            current = next;
            continue;
        }

        let file = File::from(next);
        let metadata = file
            .metadata()
            .map_err(|error| inspection_error(display_path.clone(), error))?;
        let identity = FileIdentity::from_open_metadata(&metadata, &display_path)?;
        return Ok(OpenedRegularFile {
            file,
            identity,
            display_path,
        });
    }
    Err(PathSafetyError::Empty)
}

#[cfg(unix)]
fn open_path_descriptor(path: *const libc::c_char, flags: i32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::open(path, flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn open_at_descriptor(
    parent: &std::os::fd::OwnedFd,
    path: *const libc::c_char,
    flags: i32,
) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;

    let fd = unsafe { libc::openat(parent.as_raw_fd(), path, flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(not(unix))]
pub fn open_regular_file_beneath(
    root: &Path,
    relative: &SafeRelativePath,
) -> Result<OpenedRegularFile, PathSafetyError> {
    let path = resolve_regular_file_no_links(root, relative)?;
    let file = File::open(&path).map_err(|error| inspection_error(path.clone(), error))?;
    let metadata = file
        .metadata()
        .map_err(|error| inspection_error(path.clone(), error))?;
    let identity = FileIdentity::from_open_metadata(&metadata, &path)?;
    Ok(OpenedRegularFile {
        file,
        identity,
        display_path: path,
    })
}

fn inspect_root(root: &Path) -> Result<(), PathSafetyError> {
    let metadata = inspect_entry(root)?;
    if !metadata.is_dir() {
        return Err(PathSafetyError::RootNotDirectory);
    }
    Ok(())
}

fn inspect_entry(path: &Path) -> Result<fs::Metadata, PathSafetyError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| PathSafetyError::Inspection {
        path: path.to_path_buf(),
        kind: error.kind(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(PathSafetyError::LinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    Ok(metadata)
}

fn inspection_error(path: PathBuf, error: io::Error) -> PathSafetyError {
    PathSafetyError::Inspection {
        path,
        kind: error.kind(),
        message: error.to_string(),
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}
