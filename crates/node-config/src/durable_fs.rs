//! Writing files so they survive a crash or a power loss.
//!
//! Replacing a file with `rename` is atomic, but the rename is only durable once
//! the directory holding the file has been fsynced: until then a power loss can
//! undo it and bring the previous file back, even though the writer already moved
//! on. The same holds for a newly created file or link. These helpers do the full
//! sequence so callers don't have to remember the directory fsync.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Atomically and durably replaces `path` with `contents`.
///
/// Writes a sibling `<path>.tmp`, fsyncs it, renames it over `path`, then fsyncs
/// the parent directory. A crash at any point leaves either the old or the new
/// file, never a partial one, and once this returns the new file survives a power
/// loss. Creates `path` if it doesn't exist; the parent directory must exist.
pub fn write_file_durably(path: &Path, contents: &[u8]) -> io::Result<()> {
    let tmp_path = path.with_added_extension("tmp");
    {
        let mut tmp = fs::File::create(&tmp_path)?;
        tmp.write_all(contents)?;
        tmp.sync_all()?;
    }
    rename_durably(&tmp_path, path)
}

/// Renames `from` to `to`, replacing `to` if it exists, and fsyncs the parent
/// directory of each so the rename survives a power loss.
pub fn rename_durably(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)?;
    sync_parent_dir(to)?;
    if parent_dir(from) != parent_dir(to) {
        sync_parent_dir(from)?;
    }
    Ok(())
}

/// Fsyncs the directory that contains `path`, which makes a create, rename or
/// link of `path` durable. The file itself must be synced separately.
pub fn sync_parent_dir(path: &Path) -> io::Result<()> {
    fs::File::open(parent_dir(path))?.sync_all()
}

/// `path.parent()`, with a bare file name meaning the current directory.
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
