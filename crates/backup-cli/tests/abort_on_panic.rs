use std::os::unix::process::ExitStatusExt;
use std::process::Command;

#[test]
#[expect(non_snake_case)]
fn backup_cli__should_abort_on_panic() {
    // Given
    let unwritable_home_dir = "/dev/null/backup-cli";

    // When
    let status = Command::new(env!("CARGO_BIN_EXE_backup-cli"))
        .args(["--home-dir", unwritable_home_dir, "generate-keys"])
        .status()
        .unwrap();

    // Then
    assert_eq!(status.signal(), Some(libc::SIGABRT));
}
