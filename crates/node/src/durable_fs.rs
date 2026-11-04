//! File writes that survive a power loss. A rename, or a newly created file, is
//! only durable once its directory is fsynced.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Atomically and durably replaces (or creates) `path` via a sibling `<path>.tmp`.
/// An existing file keeps its permissions; a new one gets the umask default.
/// The parent directory must exist.
pub fn write_file_durably(path: &Path, contents: &[u8]) -> io::Result<()> {
    let permissions = match fs::metadata(path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    write_tmp_and_rename(path, contents, permissions)
}

/// Like [`write_file_durably`], but `path` ends up with `permissions`.
pub fn write_file_durably_with_permissions(
    path: &Path,
    contents: &[u8],
    permissions: fs::Permissions,
) -> io::Result<()> {
    write_tmp_and_rename(path, contents, Some(permissions))
}

fn write_tmp_and_rename(
    path: &Path,
    contents: &[u8],
    permissions: Option<fs::Permissions>,
) -> io::Result<()> {
    let tmp_path = path.with_added_extension("tmp");
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        if permissions.is_some() {
            // Owner-only until `permissions` is applied, so secret contents are never exposed.
            options.mode(0o600);
        }
        let mut tmp = options.open(&tmp_path)?;
        if let Some(permissions) = permissions {
            tmp.set_permissions(permissions)?;
        }
        tmp.write_all(contents)?;
        tmp.sync_all()?;
    }
    rename_durably(&tmp_path, path)
}

/// Renames `from` over `to`, then fsyncs the parent directory of `to`, and of
/// `from` when it differs: the rename changes both directories' entries.
pub fn rename_durably(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)?;
    sync_parent_dir(to)?;
    if parent_dir(from) != parent_dir(to) {
        sync_parent_dir(from)?;
    }
    Ok(())
}

/// Fsyncs the directory containing `path`. Does not sync the file itself.
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    fs::File::open(parent_dir(path))?.sync_all()
}

/// A bare file name's parent is `.`, not the empty path.
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_file_durably__should_create_missing_file() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.json");

        // When
        write_file_durably(&path, b"new").unwrap();

        // Then
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn write_file_durably__should_replace_existing_contents() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.json");
        fs::write(&path, b"a much longer old content").unwrap();

        // When
        write_file_durably(&path, b"new").unwrap();

        // Then
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn write_file_durably__should_not_leave_temp_file() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.json");

        // When
        write_file_durably(&path, b"new").unwrap();

        // Then
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec!["file.json"]);
    }

    #[test]
    fn write_file_durably__should_keep_existing_permissions() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        // When
        write_file_durably(&path, b"new").unwrap();

        // Then
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn write_file_durably_with_permissions__should_apply_permissions() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        // When
        write_file_durably_with_permissions(&path, b"new", fs::Permissions::from_mode(0o600))
            .unwrap();

        // Then
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn write_file_durably__should_fail_when_parent_dir_is_missing() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("file.json");

        // When
        let result = write_file_durably(&path, b"new");

        // Then
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn rename_durably__should_move_file_across_directories() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("a").join("file");
        let to = dir.path().join("b").join("file");
        fs::create_dir_all(from.parent().unwrap()).unwrap();
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::write(&from, b"x").unwrap();

        // When
        rename_durably(&from, &to).unwrap();

        // Then
        assert!(!from.exists());
        assert_eq!(fs::read(&to).unwrap(), b"x");
    }

    #[test]
    fn sync_parent_dir__should_fail_when_parent_dir_is_missing() {
        // Given
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("file");

        // When
        let result = sync_parent_dir(&path);

        // Then
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn parent_dir__should_be_current_dir_for_bare_file_name() {
        // Given
        let path = Path::new("file");

        // When
        let parent = parent_dir(path);

        // Then
        assert_eq!(parent, Path::new("."));
    }
}
