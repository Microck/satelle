use super::*;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

struct BackupFixture {
    _test_state: crate::TestStateDir,
    state_root: PathBuf,
    backup_file_names: Vec<String>,
}

impl BackupFixture {
    fn new(backup_count: usize) -> Self {
        let test_state = crate::TestStateDir::new().expect("create test state directory");
        let state_root = test_state.path().to_path_buf();
        let (connection, ownership_lock, state_directory) =
            open_parts(&state_root).expect("open fixture store");
        let source_schema_version = MIGRATIONS.last().expect("migration registry").version;
        for _ in 0..backup_count {
            create_migration_backup(
                &connection,
                &state_root,
                &state_directory,
                source_schema_version,
            )
            .expect("create fixture backup");
        }
        drop(connection);
        drop(ownership_lock);
        drop(state_directory);

        let mut backup_file_names = fs::read_dir(&state_root)
            .expect("read state directory")
            .map(|entry| entry.expect("read state entry").file_name())
            .filter_map(|name| name.into_string().ok())
            .filter(|name| parse_migration_backup_file_name(name).is_some())
            .collect::<Vec<_>>();
        backup_file_names.sort_by_key(|name| {
            parse_migration_backup_file_name(name)
                .expect("fixture backup filename")
                .backup_id
        });
        assert_eq!(backup_count, backup_file_names.len());

        Self {
            _test_state: test_state,
            state_root,
            backup_file_names,
        }
    }

    fn backup_file_name(&self) -> &str {
        self.backup_file_names
            .last()
            .expect("fixture contains a backup")
    }

    fn manifest_path(&self, backup_file_name: &str) -> PathBuf {
        self.state_root.join(format!("{backup_file_name}.json"))
    }

    fn manifest(&self, backup_file_name: &str) -> MigrationBackupManifest {
        serde_json::from_slice(
            &fs::read(self.manifest_path(backup_file_name)).expect("read backup manifest"),
        )
        .expect("parse backup manifest")
    }

    fn write_manifest(&self, backup_file_name: &str, manifest: &MigrationBackupManifest) {
        let manifest_path = self.manifest_path(backup_file_name);
        let mut bytes = serde_json::to_vec(manifest).expect("serialize backup manifest");
        bytes.push(b'\n');
        write_private_file(&manifest_path, &bytes);
    }

    fn state_directory(&self) -> StateDirectory {
        prepare_state_root(&self.state_root).expect("prepare fixture state directory")
    }
}

#[test]
fn manifest_filename_digest_schema_and_compatibility_are_validated() {
    let fixture = BackupFixture::new(1);
    let state_directory = fixture.state_directory();
    let backup_file_name = fixture.backup_file_name();
    let validated =
        validate_migration_backup(&fixture.state_root, &state_directory, backup_file_name)
            .expect("validate fixture backup");
    let manifest = fixture.manifest(backup_file_name);

    assert_eq!(backup_file_name, validated.backup_file_name);
    assert_eq!(BACKUP_FORMAT_VERSION, manifest.manifest_version);
    assert_eq!(backup_file_name, manifest.backup_file);
    assert_eq!(
        parse_migration_backup_file_name(backup_file_name)
            .expect("parse backup filename")
            .schema_version,
        manifest.source_schema_version
    );
    assert!(is_sha256_digest(&manifest.source_database_digest));
    assert_eq!("sqlite3", manifest.restore_compatibility.database_format);
    assert_eq!(
        manifest.source_schema_version,
        manifest.restore_compatibility.schema_version
    );
    assert!(manifest.restore_compatibility.explicit_restore_required);

    let original_manifest = manifest;
    let mut wrong_filename = original_manifest.clone();
    wrong_filename.backup_file = "satelle.sqlite3.migration-v8-wrong.backup".to_owned();
    fixture.write_manifest(backup_file_name, &wrong_filename);
    assert_eq!(
        StorageErrorKind::InvalidInput,
        validate_migration_backup(&fixture.state_root, &state_directory, backup_file_name)
            .expect_err("reject mismatched manifest filename")
            .kind()
    );

    let mut wrong_digest = original_manifest.clone();
    wrong_digest.source_database_digest = format!("sha256:{}", "0".repeat(64));
    fixture.write_manifest(backup_file_name, &wrong_digest);
    assert_eq!(
        StorageErrorKind::IntegrityCheckFailed,
        validate_migration_backup(&fixture.state_root, &state_directory, backup_file_name)
            .expect_err("reject mismatched digest")
            .kind()
    );

    let mut wrong_schema = original_manifest.clone();
    wrong_schema.source_schema_version -= 1;
    wrong_schema.restore_compatibility.schema_version -= 1;
    fixture.write_manifest(backup_file_name, &wrong_schema);
    assert_eq!(
        StorageErrorKind::InvalidInput,
        validate_migration_backup(&fixture.state_root, &state_directory, backup_file_name)
            .expect_err("reject mismatched filename schema")
            .kind()
    );

    let mut unsupported_manifest_version = original_manifest.clone();
    unsupported_manifest_version.manifest_version += 1;
    fixture.write_manifest(backup_file_name, &unsupported_manifest_version);
    assert_eq!(
        StorageErrorKind::InvalidInput,
        validate_migration_backup(&fixture.state_root, &state_directory, backup_file_name)
            .expect_err("reject unsupported manifest version")
            .kind()
    );

    let mut incompatible = original_manifest;
    incompatible.restore_compatibility.database_format = "future-store".to_owned();
    fixture.write_manifest(backup_file_name, &incompatible);
    assert_eq!(
        StorageErrorKind::InvalidInput,
        validate_migration_backup(&fixture.state_root, &state_directory, backup_file_name)
            .expect_err("reject incompatible manifest")
            .kind()
    );
}

#[test]
fn validation_rejects_an_internally_consistent_manifest_with_the_wrong_actual_schema() {
    let fixture = BackupFixture::new(1);
    let source_name = fixture.backup_file_name().to_owned();
    let claimed_name = "satelle.sqlite3.migration-v7-0198a146-5ec2-7dd5-b51c-7d5e241e5880.backup";
    let source_bytes =
        fs::read(fixture.state_root.join(&source_name)).expect("read schema-mismatch source");
    write_private_file(&fixture.state_root.join(claimed_name), &source_bytes);
    let mut manifest = fixture.manifest(&source_name);
    manifest.backup_file = claimed_name.to_owned();
    manifest.source_schema_version = 7;
    manifest.restore_compatibility.schema_version = 7;
    fixture.write_manifest(claimed_name, &manifest);
    let state_directory = fixture.state_directory();

    assert_eq!(
        StorageErrorKind::IntegrityCheckFailed,
        validate_migration_backup(&fixture.state_root, &state_directory, claimed_name)
            .expect_err("reject database whose actual schema is newer than its manifest")
            .kind()
    );
}

#[test]
fn validation_rejects_a_wrong_migration_checksum_with_a_matching_file_digest() {
    let fixture = BackupFixture::new(1);
    let backup_file_name = fixture.backup_file_name().to_owned();
    let backup_path = fixture.state_root.join(&backup_file_name);
    let connection = Connection::open(&backup_path).expect("open backup for checksum corruption");
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .expect("use a self-contained checksum-corruption transaction");
    connection
        .execute(
            "UPDATE schema_migrations SET checksum = 'fnv1a64:0000000000000000' WHERE version = 8",
            [],
        )
        .expect("corrupt only the migration checksum");
    drop(connection);
    let mut manifest = fixture.manifest(&backup_file_name);
    let backup_file = File::open(&backup_path).expect("open checksum-corrupt backup");
    manifest.source_database_digest =
        digest_file(&backup_file, StorageErrorKind::IntegrityCheckFailed)
            .expect("digest checksum-corrupt backup");
    fixture.write_manifest(&backup_file_name, &manifest);
    let state_directory = fixture.state_directory();

    assert_eq!(
        StorageErrorKind::IntegrityCheckFailed,
        validate_migration_backup(&fixture.state_root, &state_directory, &backup_file_name)
            .expect_err("reject wrong migration checksum despite matching file digest")
            .kind()
    );
}

#[cfg(unix)]
#[test]
fn validation_rejects_a_digest_to_sqlite_path_swap() {
    let fixture = BackupFixture::new(1);
    let backup_file_name = fixture.backup_file_name().to_owned();
    let backup_path = fixture.state_root.join(&backup_file_name);
    let original_path = fixture
        .state_root
        .join(format!("{backup_file_name}.digest-object"));
    let state_directory = fixture.state_directory();

    let error = validate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &backup_file_name,
        |step| {
            if step == ValidationStep::DigestVerified {
                fs::rename(&backup_path, &original_path).expect("move digested object aside");
                fs::copy(&original_path, &backup_path).expect("install identity-distinct object");
                fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))
                    .expect("make replacement private");
            }
            Ok(())
        },
    )
    .expect_err("reject digest-to-SQLite pathname swap");

    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    assert!(original_path.is_file());
    assert!(backup_path.is_file());
    assert_eq!(
        fs::read(&original_path).expect("read digested physical object"),
        fs::read(&backup_path).expect("read identity-distinct replacement")
    );
}

#[cfg(windows)]
#[test]
fn windows_validation_guard_blocks_digest_to_sqlite_replacement() {
    let fixture = BackupFixture::new(1);
    let backup_file_name = fixture.backup_file_name().to_owned();
    let backup_path = fixture.state_root.join(&backup_file_name);
    let moved_path = fixture.state_root.join(format!("{backup_file_name}.moved"));
    let state_directory = fixture.state_directory();
    let mut replacement_was_blocked = false;

    validate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &backup_file_name,
        |step| {
            if step == ValidationStep::DigestVerified {
                replacement_was_blocked = fs::rename(&backup_path, &moved_path).is_err();
            }
            Ok(())
        },
    )
    .expect("validate the guarded physical object");

    assert!(replacement_was_blocked);
    assert!(backup_path.is_file());
    assert!(!moved_path.exists());
}

#[cfg(unix)]
#[test]
fn restore_validation_rejects_symlink_nonregular_and_nonprivate_inputs() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let fixture = BackupFixture::new(1);
    let source_name = fixture.backup_file_name().to_owned();
    let source_manifest = fixture.manifest(&source_name);
    let state_directory = fixture.state_directory();
    let candidates = [
        (
            "satelle.sqlite3.migration-v8-0198a146-5ec2-7dd5-b51c-7d5e241e5890.backup",
            "symlink",
        ),
        (
            "satelle.sqlite3.migration-v8-0198a146-5ec2-7dd5-b51c-7d5e241e5891.backup",
            "directory",
        ),
        (
            "satelle.sqlite3.migration-v8-0198a146-5ec2-7dd5-b51c-7d5e241e5892.backup",
            "nonprivate",
        ),
    ];

    for (candidate, kind) in candidates {
        let candidate_path = fixture.state_root.join(candidate);
        match kind {
            "symlink" => symlink(&source_name, &candidate_path).expect("create backup symlink"),
            "directory" => fs::create_dir(&candidate_path).expect("create backup directory"),
            "nonprivate" => {
                fs::copy(fixture.state_root.join(&source_name), &candidate_path)
                    .expect("copy nonprivate backup");
                fs::set_permissions(&candidate_path, fs::Permissions::from_mode(0o644))
                    .expect("make backup nonprivate");
            }
            _ => unreachable!(),
        }
        let mut manifest = source_manifest.clone();
        manifest.backup_file = candidate.to_owned();
        fixture.write_manifest(candidate, &manifest);

        assert_eq!(
            StorageErrorKind::UnsafeStatePath,
            validate_migration_backup(&fixture.state_root, &state_directory, candidate)
                .expect_err("reject unsafe backup input")
                .kind()
        );
    }

    assert_eq!(
        0o644,
        fs::metadata(fixture.state_root.join(candidates[2].0))
            .expect("read nonprivate mode")
            .permissions()
            .mode()
            & 0o777
    );
}

#[test]
fn restore_validation_rejects_hardlinked_inputs() {
    let fixture = BackupFixture::new(1);
    let source_name = fixture.backup_file_name().to_owned();
    let hardlink_name = "satelle.sqlite3.migration-v8-0198a146-5ec2-7dd5-b51c-7d5e241e5893.backup";
    fs::hard_link(
        fixture.state_root.join(&source_name),
        fixture.state_root.join(hardlink_name),
    )
    .expect("create backup hardlink");
    let mut manifest = fixture.manifest(&source_name);
    manifest.backup_file = hardlink_name.to_owned();
    fixture.write_manifest(hardlink_name, &manifest);
    let state_directory = fixture.state_directory();

    assert_eq!(
        StorageErrorKind::UnsafeStatePath,
        validate_migration_backup(&fixture.state_root, &state_directory, hardlink_name)
            .expect_err("reject multiply linked backup")
            .kind()
    );
}

#[cfg(windows)]
#[test]
fn restore_validation_rejects_windows_reparse_and_broadened_dacl_inputs() {
    let fixture = BackupFixture::new(1);
    let source_name = fixture.backup_file_name().to_owned();
    let source_manifest = fixture.manifest(&source_name);
    let reparse_name = "satelle.sqlite3.migration-v8-0198a146-5ec2-7dd5-b51c-7d5e241e5894.backup";
    super::windows::create_file_symlink_for_test(
        &fixture.state_root.join(&source_name),
        &fixture.state_root.join(reparse_name),
    )
    .expect("create backup reparse point");
    let mut reparse_manifest = source_manifest.clone();
    reparse_manifest.backup_file = reparse_name.to_owned();
    fixture.write_manifest(reparse_name, &reparse_manifest);

    let broad_dacl_name =
        "satelle.sqlite3.migration-v8-0198a146-5ec2-7dd5-b51c-7d5e241e5895.backup";
    fs::copy(
        fixture.state_root.join(&source_name),
        fixture.state_root.join(broad_dacl_name),
    )
    .expect("copy broad-DACL backup");
    super::windows::broaden_leaf_dacl_for_test(&fixture.state_root.join(broad_dacl_name))
        .expect("broaden backup DACL");
    let mut broad_dacl_manifest = source_manifest;
    broad_dacl_manifest.backup_file = broad_dacl_name.to_owned();
    fixture.write_manifest(broad_dacl_name, &broad_dacl_manifest);
    let state_directory = fixture.state_directory();

    for candidate in [reparse_name, broad_dacl_name] {
        assert_eq!(
            StorageErrorKind::UnsafeStatePath,
            validate_migration_backup(&fixture.state_root, &state_directory, candidate)
                .expect_err("reject unsafe Windows backup")
                .kind()
        );
    }
}

fn replace_active_store_with_marker(fixture: &BackupFixture, marker: &[u8]) {
    fs::write(fixture.state_root.join(DATABASE_FILE_NAME), marker).expect("replace active store");
}

fn write_distinct_active_sidecars(fixture: &BackupFixture) -> Vec<(String, Vec<u8>)> {
    PROTECTED_FILE_NAMES[2..]
        .iter()
        .enumerate()
        .map(|(index, file_name)| {
            let bytes = format!("sidecar-{index}-{}", Uuid::now_v7()).into_bytes();
            write_private_file(&fixture.state_root.join(file_name), &bytes);
            ((*file_name).to_owned(), bytes)
        })
        .collect()
}

fn assert_activation_matches_backup(fixture: &BackupFixture, outcome: &RestoreActivation) {
    assert_eq!(
        fs::read(fixture.state_root.join(fixture.backup_file_name())).expect("read backup"),
        fs::read(fixture.state_root.join(DATABASE_FILE_NAME)).expect("read active store")
    );
    assert!(
        fixture
            .state_root
            .join(&outcome.failed_store_file_name)
            .is_file()
    );
}

#[test]
fn activation_preserves_the_failed_store_before_atomic_replacement() {
    let fixture = BackupFixture::new(1);
    let failed_store: &[u8] = b"failed store requiring operator recovery";
    replace_active_store_with_marker(&fixture, failed_store);
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup");

    let outcome = activate_migration_backup(&fixture.state_root, &state_directory, &validated)
        .expect("activate backup");

    assert_activation_matches_backup(&fixture, &outcome);
    assert_eq!(
        failed_store,
        fs::read(fixture.state_root.join(outcome.failed_store_file_name))
            .expect("read preserved failed store")
    );
}

#[test]
fn activation_rejects_a_candidate_swap_before_staging_without_touching_active_state() {
    let fixture = BackupFixture::new(1);
    let active_store: &[u8] = b"active store before candidate swap";
    replace_active_store_with_marker(&fixture, active_store);
    let sidecars = write_distinct_active_sidecars(&fixture);
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate original candidate");
    let original_candidate = fixture
        .state_root
        .join(format!("{}.swapped-out", fixture.backup_file_name()));

    let error = activate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &validated,
        |step| {
            if step == ActivationStep::CandidateValidated {
                fs::rename(
                    fixture.state_root.join(fixture.backup_file_name()),
                    &original_candidate,
                )
                .expect("move validated candidate aside");
                write_private_file(
                    &fixture.state_root.join(fixture.backup_file_name()),
                    b"swapped replacement",
                );
            }
            Ok(())
        },
    )
    .expect_err("reject swapped candidate during staged validation");

    assert_eq!(StorageErrorKind::IntegrityCheckFailed, error.kind());
    assert_eq!(
        active_store,
        fs::read(fixture.state_root.join(DATABASE_FILE_NAME)).expect("read unchanged active store")
    );
    assert_eq!(
        b"swapped replacement".as_slice(),
        fs::read(fixture.state_root.join(fixture.backup_file_name()))
            .expect("read replacement candidate")
    );
    assert!(original_candidate.is_file());
    for (file_name, bytes) in sidecars {
        assert_eq!(
            bytes,
            fs::read(fixture.state_root.join(file_name)).expect("read unchanged active sidecar")
        );
    }
    assert!(
        !existing_files(&fixture.state_root)
            .iter()
            .any(|name| name.starts_with("satelle.sqlite3.failed-"))
    );
}

#[test]
fn activation_restores_the_prior_active_store_after_an_inside_install_race() {
    let fixture = BackupFixture::new(1);
    let prior_active: &[u8] = b"active store before staged install race";
    replace_active_store_with_marker(&fixture, prior_active);
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup");
    let mut swapped_staged = None;

    let error = activate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &validated,
        |step| {
            if step == ActivationStep::BeforeStagedInstallMove {
                let staged_name = existing_files(&fixture.state_root)
                    .into_iter()
                    .find(|name| name.ends_with(".staged"))
                    .expect("staged leaf before install");
                let moved_name = format!("{staged_name}.swapped-out");
                fs::rename(
                    fixture.state_root.join(&staged_name),
                    fixture.state_root.join(&moved_name),
                )
                .expect("move validated staged object aside");
                write_private_file(
                    &fixture.state_root.join(&staged_name),
                    b"identity-distinct staged replacement",
                );
                swapped_staged = Some(moved_name);
            }
            Ok(())
        },
    )
    .expect_err("reject staged replacement and roll back active primary");

    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    assert_eq!(
        prior_active,
        fs::read(fixture.state_root.join(DATABASE_FILE_NAME))
            .expect("read restored prior active store")
    );
    assert!(
        fixture
            .state_root
            .join(swapped_staged.expect("swap occurred"))
            .is_file()
    );
    let rejected_name = existing_files(&fixture.state_root)
        .into_iter()
        .find(|name| name.contains(".rejected-"))
        .expect("quarantined staged replacement name");
    assert_eq!(
        b"identity-distinct staged replacement".as_slice(),
        fs::read(fixture.state_root.join(rejected_name))
            .expect("read quarantined staged replacement")
    );
}

#[test]
fn activation_restores_the_prior_active_store_after_post_install_mismatch() {
    let fixture = BackupFixture::new(1);
    let prior_active: &[u8] = b"active store before post-install mismatch";
    replace_active_store_with_marker(&fixture, prior_active);
    let expected_installed = fs::read(fixture.state_root.join(fixture.backup_file_name()))
        .expect("read expected installed backup");
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup");
    let installed_aside = fixture
        .state_root
        .join("installed-before-validation.sqlite3");

    let error = activate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &validated,
        |step| {
            if step == ActivationStep::InstalledBeforeValidation {
                fs::rename(
                    fixture.state_root.join(DATABASE_FILE_NAME),
                    &installed_aside,
                )
                .expect("move installed object before post-validation");
                write_private_file(
                    &fixture.state_root.join(DATABASE_FILE_NAME),
                    b"post-install identity mismatch",
                );
            }
            Ok(())
        },
    )
    .expect_err("roll back a post-install identity mismatch");

    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    assert_eq!(
        prior_active,
        fs::read(fixture.state_root.join(DATABASE_FILE_NAME))
            .expect("read restored prior active store")
    );
    assert_eq!(
        expected_installed,
        fs::read(installed_aside).expect("read recoverable installed object")
    );
    let rejected_name = existing_files(&fixture.state_root)
        .into_iter()
        .find(|name| name.contains(".rejected-"))
        .expect("post-install replacement quarantine");
    assert_eq!(
        b"post-install identity mismatch".as_slice(),
        fs::read(fixture.state_root.join(rejected_name))
            .expect("read quarantined post-install replacement")
    );
}

#[test]
fn activation_fsyncs_recovery_state_and_then_atomically_replaces_the_store() {
    let fixture = BackupFixture::new(1);
    replace_active_store_with_marker(&fixture, b"failed store");
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup");
    let mut observed_steps = Vec::new();

    let outcome = activate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &validated,
        |step| {
            observed_steps.push(step);
            Ok(())
        },
    )
    .expect("activate backup");

    assert_eq!(
        [
            ActivationStep::CandidateValidated,
            ActivationStep::StagedValidated,
            ActivationStep::SidecarsMovedDurably,
            ActivationStep::RecoveryStateDurable,
            ActivationStep::BeforeStagedInstallMove,
            ActivationStep::InstalledBeforeValidation,
            ActivationStep::ReplacementDurable,
        ],
        observed_steps.as_slice()
    );
    assert_activation_matches_backup(&fixture, &outcome);
}

#[test]
fn activation_moves_byte_distinct_sidecars_to_durable_failed_names() {
    let fixture = BackupFixture::new(1);
    replace_active_store_with_marker(&fixture, b"failed store with sidecars");
    let sidecars = write_distinct_active_sidecars(&fixture);
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup");

    let outcome = activate_migration_backup(&fixture.state_root, &state_directory, &validated)
        .expect("activate backup with sidecars");

    assert_eq!(sidecars.len(), outcome.failed_sidecar_file_names.len());
    for ((active_name, expected_bytes), failed_name) in
        sidecars.iter().zip(&outcome.failed_sidecar_file_names)
    {
        assert!(!fixture.state_root.join(active_name).exists());
        assert_eq!(
            expected_bytes,
            &fs::read(fixture.state_root.join(failed_name)).expect("read failed sidecar")
        );
    }
    assert_activation_matches_backup(&fixture, &outcome);
}

#[test]
fn activation_errors_restore_active_sidecars() {
    let fixture = BackupFixture::new(1);
    let active_store: &[u8] = b"active primary before sidecar move interruption";
    replace_active_store_with_marker(&fixture, active_store);
    let sidecars = write_distinct_active_sidecars(&fixture);
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup");

    let error = activate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &validated,
        |step| {
            if step == ActivationStep::SidecarsMovedDurably {
                Err(StorageError::for_test(StorageErrorKind::OperationFailed))
            } else {
                Ok(())
            }
        },
    )
    .expect_err("interrupt after durable sidecar moves");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    assert_eq!(
        active_store,
        fs::read(fixture.state_root.join(DATABASE_FILE_NAME)).expect("read active primary")
    );
    let files = existing_files(&fixture.state_root);
    assert!(files.iter().any(|name| name.ends_with(".staged")));
    for (active_name, expected_bytes) in sidecars {
        assert_eq!(
            expected_bytes,
            fs::read(fixture.state_root.join(active_name)).expect("read restored active sidecar")
        );
    }
    assert!(!files.iter().any(|name| {
        name.starts_with("satelle.sqlite3.failed-")
            && (name.ends_with("-wal") || name.ends_with("-shm"))
    }));
    validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("original restore point remains valid");

    let fixture = BackupFixture::new(1);
    let sidecars = write_distinct_active_sidecars(&fixture);
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup for staged revalidation failure");

    activate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &validated,
        |step| {
            if step == ActivationStep::SidecarsMovedDurably {
                let staged_name = existing_files(&fixture.state_root)
                    .into_iter()
                    .find(|name| name.ends_with(".staged"))
                    .expect("staged restore file");
                fs::write(
                    fixture.state_root.join(staged_name),
                    b"changed staged restore",
                )
                .expect("invalidate staged restore");
            }
            Ok(())
        },
    )
    .expect_err("reject changed staged restore");

    for (active_name, expected_bytes) in sidecars {
        assert_eq!(
            expected_bytes,
            fs::read(fixture.state_root.join(active_name))
                .expect("read sidecar restored after revalidation failure")
        );
    }
}

#[test]
fn interruption_before_replacement_leaves_a_recoverable_store() {
    let fixture = BackupFixture::new(1);
    let failed_store: &[u8] = b"store before interrupted restore";
    replace_active_store_with_marker(&fixture, failed_store);
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup");

    let error = activate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &validated,
        |step| {
            if step == ActivationStep::RecoveryStateDurable {
                Err(StorageError::for_test(StorageErrorKind::OperationFailed))
            } else {
                Ok(())
            }
        },
    )
    .expect_err("interrupt restore before replacement");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    assert_eq!(
        failed_store,
        fs::read(fixture.state_root.join(DATABASE_FILE_NAME)).expect("read active store")
    );
    let files = existing_files(&fixture.state_root);
    assert!(
        !files
            .iter()
            .any(|name| name.starts_with("satelle.sqlite3.failed-") && name.ends_with(".sqlite3"))
    );
    let staged_name = files
        .iter()
        .find(|name| name.starts_with("satelle.sqlite3.restore-") && name.ends_with(".staged"))
        .expect("validated staged backup name");
    validate_migration_backup_at(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
        staged_name,
        &format!("{}.json", fixture.backup_file_name()),
    )
    .expect("staged backup remains independently valid");
    validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("original backup remains recoverable");
}

#[test]
fn interruption_after_replacement_leaves_both_active_and_failed_stores_recoverable() {
    let fixture = BackupFixture::new(1);
    let failed_store: &[u8] = b"store before post-replacement interruption";
    replace_active_store_with_marker(&fixture, failed_store);
    let expected_active = fs::read(fixture.state_root.join(fixture.backup_file_name()))
        .expect("read expected restored bytes");
    let state_directory = fixture.state_directory();
    let validated = validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("validate backup");

    let error = activate_migration_backup_with_hook(
        &fixture.state_root,
        &state_directory,
        &validated,
        |step| {
            if step == ActivationStep::ReplacementDurable {
                Err(StorageError::for_test(StorageErrorKind::OperationFailed))
            } else {
                Ok(())
            }
        },
    )
    .expect_err("interrupt after durable replacement");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    assert_eq!(
        expected_active,
        fs::read(fixture.state_root.join(DATABASE_FILE_NAME)).expect("read restored active store")
    );
    let failed_store_name = existing_files(&fixture.state_root)
        .into_iter()
        .find(|name| name.starts_with("satelle.sqlite3.failed-") && name.ends_with(".sqlite3"))
        .expect("durable failed store name");
    assert_eq!(
        failed_store,
        fs::read(fixture.state_root.join(failed_store_name)).expect("read failed store")
    );
    validate_migration_backup(
        &fixture.state_root,
        &state_directory,
        fixture.backup_file_name(),
    )
    .expect("source restore point remains valid");
}

fn existing_files(path: &Path) -> Vec<String> {
    let mut files = fs::read_dir(path)
        .expect("read directory")
        .map(|entry| entry.expect("read directory entry").file_name())
        .filter_map(|name| name.into_string().ok())
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    let state_root = path.parent().expect("private test file has a parent");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("private test file has a UTF-8 leaf name");
    let state_directory = prepare_state_root(state_root).expect("prepare private test directory");
    let mut file = open_private_leaf(
        &state_directory,
        file_name,
        LeafOpenMode::CreateIfMissing,
        StorageErrorKind::OperationFailed,
    )
    .expect("open private test file")
    .expect("private test file descriptor");
    file.set_len(0).expect("truncate private test file");
    file.write_all(bytes).expect("write private test file");
    file.sync_all().expect("sync private test file");
}

fn validated_backup_names(fixture: &BackupFixture) -> Vec<String> {
    let state_directory = fixture.state_directory();
    let mut names = fixture
        .backup_file_names
        .iter()
        .filter(|name| {
            validate_migration_backup(&fixture.state_root, &state_directory, name).is_ok()
        })
        .cloned()
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn cleanup_tombstone_names(fixture: &BackupFixture) -> Vec<String> {
    existing_files(&fixture.state_root)
        .into_iter()
        .filter(|name| name.starts_with("satelle.sqlite3.cleanup~"))
        .collect()
}

#[test]
fn cleanup_deleting_names_round_trip_without_increasing_path_pressure() {
    let key = CleanupTombstoneKey {
        schema_version: 8,
        backup_id: Uuid::parse_str("0198a146-5ec2-7dd5-b51c-7d5e241e5880")
            .expect("valid version 7 backup id"),
        cleanup_id: Uuid::parse_str("0198a146-5ec2-7dd5-b51c-7d5e241e5881")
            .expect("valid version 7 cleanup id"),
        backup_fingerprint: "0123456789abcdef0123456789abcdef".to_owned(),
        manifest_fingerprint: "fedcba9876543210fedcba9876543210".to_owned(),
    };

    for deleting_kind in [CleanupDeletingKind::Backup, CleanupDeletingKind::Manifest] {
        let deleting_name = cleanup_deleting_file_name(&key, deleting_kind);
        let tombstone_name = deleting_name.replace(".deleting", ".tombstone");

        assert_eq!(
            Some((key.clone(), deleting_kind)),
            parse_cleanup_deleting_file_name(&deleting_name)
        );
        assert!(deleting_name.len() < tombstone_name.len());
        assert!(
            parse_cleanup_deleting_file_name(&format!(
                "{deleting_name}~0198a146-5ec2-7dd5-b51c-7d5e241e5882"
            ))
            .is_none()
        );
        assert!(parse_cleanup_deleting_file_name(&format!("{deleting_name}~garbage")).is_none());
    }
}

#[test]
fn cleanup_retains_the_newest_validated_backup_and_one_previous_backup() {
    let fixture = BackupFixture::new(3);
    let state_directory = fixture.state_directory();

    let removed = cleanup_migration_backups(&fixture.state_root, &state_directory)
        .expect("clean up old backups");

    assert_eq!(vec![fixture.backup_file_names[0].clone()], removed);
    for backup_file_name in &fixture.backup_file_names[1..] {
        assert!(fixture.state_root.join(backup_file_name).is_file());
        assert!(fixture.manifest_path(backup_file_name).is_file());
        validate_migration_backup(&fixture.state_root, &state_directory, backup_file_name)
            .expect("retained restore point remains valid");
    }
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );
}

#[test]
fn cleanup_never_deletes_the_only_valid_restore_point() {
    let fixture = BackupFixture::new(1);
    let state_directory = fixture.state_directory();
    let files_before = existing_files(&fixture.state_root);

    let removed =
        cleanup_migration_backups(&fixture.state_root, &state_directory).expect("clean up backups");

    assert!(removed.is_empty());
    assert_eq!(files_before, existing_files(&fixture.state_root));
}

#[test]
fn cleanup_identity_swap_never_deletes_the_replacement() {
    let fixture = BackupFixture::new(3);
    let oldest = fixture.backup_file_names[0].clone();
    let original_bytes = fs::read(fixture.state_root.join(&oldest)).expect("read oldest backup");
    let swapped_out = fixture.state_root.join(format!("{oldest}.swapped-out"));
    let state_directory = fixture.state_directory();

    let error =
        cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
            if step == CleanupStep::CandidateValidated {
                fs::rename(fixture.state_root.join(&oldest), &swapped_out)
                    .expect("move cleanup candidate aside");
                write_private_file(
                    &fixture.state_root.join(&oldest),
                    b"replacement that cleanup must not delete",
                );
            }
            Ok(())
        })
        .expect_err("reject cleanup identity swap");

    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    assert_eq!(
        b"replacement that cleanup must not delete".as_slice(),
        fs::read(fixture.state_root.join(&oldest)).expect("read preserved replacement")
    );
    assert_eq!(
        original_bytes,
        fs::read(swapped_out).expect("read swapped-out original")
    );
    let replacement_tombstone = cleanup_tombstone_names(&fixture)
        .into_iter()
        .find(|name| name.ends_with("~backup.tombstone"))
        .expect("identity-distinct replacement tombstone");
    assert_eq!(
        b"replacement that cleanup must not delete".as_slice(),
        fs::read(fixture.state_root.join(replacement_tombstone))
            .expect("read preserved replacement tombstone")
    );
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );
}

#[test]
fn cleanup_inside_quarantine_race_preserves_the_replacement() {
    let fixture = BackupFixture::new(3);
    let oldest = fixture.backup_file_names[0].clone();
    let original_bytes = fs::read(fixture.state_root.join(&oldest)).expect("read oldest backup");
    let swapped_out = fixture.state_root.join(format!("{oldest}.inside-race"));
    let state_directory = fixture.state_directory();

    let error =
        cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
            if step == CleanupStep::BeforeBackupQuarantineMove {
                fs::rename(fixture.state_root.join(&oldest), &swapped_out)
                    .expect("move selected backup inside quarantine primitive");
                write_private_file(
                    &fixture.state_root.join(&oldest),
                    b"replacement moved but never deleted",
                );
            }
            Ok(())
        })
        .expect_err("reject identity-distinct quarantine result");

    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    assert_eq!(
        original_bytes,
        fs::read(swapped_out).expect("read selected original")
    );
    let tombstone = cleanup_tombstone_names(&fixture)
        .into_iter()
        .find(|name| name.ends_with("~backup.tombstone"))
        .expect("replacement quarantine tombstone");
    assert_eq!(
        b"replacement moved but never deleted".as_slice(),
        fs::read(fixture.state_root.join(tombstone)).expect("read preserved replacement")
    );
}

#[test]
fn cleanup_second_quarantine_move_failure_restores_the_selected_pair() {
    let fixture = BackupFixture::new(3);
    let oldest = fixture.backup_file_names[0].clone();
    let oldest_bytes = fs::read(fixture.state_root.join(&oldest)).expect("read oldest backup");
    let manifest_bytes = fs::read(fixture.manifest_path(&oldest)).expect("read oldest manifest");
    let state_directory = fixture.state_directory();
    let mut blocking_manifest_tombstone = None;

    let error =
        cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
            if step == CleanupStep::BeforeManifestQuarantineMove {
                let backup_tombstone = cleanup_tombstone_names(&fixture)
                    .into_iter()
                    .find(|name| name.ends_with("~backup.tombstone"))
                    .expect("backup tombstone before second move");
                let manifest_tombstone =
                    backup_tombstone.replace("~backup.tombstone", "~manifest.tombstone");
                write_private_file(
                    &fixture.state_root.join(&manifest_tombstone),
                    b"no-clobber blocker",
                );
                blocking_manifest_tombstone = Some(manifest_tombstone);
            }
            Ok(())
        })
        .expect_err("force the real second quarantine move to fail no-clobber");

    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    assert_eq!(
        oldest_bytes,
        fs::read(fixture.state_root.join(&oldest)).expect("read restored backup")
    );
    assert_eq!(
        manifest_bytes,
        fs::read(fixture.manifest_path(&oldest)).expect("read untouched manifest")
    );
    let blocking_manifest_tombstone = blocking_manifest_tombstone.expect("blocker was installed");
    assert_eq!(
        b"no-clobber blocker".as_slice(),
        fs::read(fixture.state_root.join(&blocking_manifest_tombstone))
            .expect("read preserved no-clobber blocker")
    );
    assert_eq!(
        vec![blocking_manifest_tombstone],
        cleanup_tombstone_names(&fixture)
    );
    validate_migration_backup(&fixture.state_root, &state_directory, &oldest)
        .expect("restored pair remains valid");
}

#[test]
fn cleanup_interruption_after_first_quarantine_is_retryable() {
    let fixture = BackupFixture::new(3);
    let oldest = fixture.backup_file_names[0].clone();
    let oldest_bytes = fs::read(fixture.state_root.join(&oldest)).expect("read oldest backup");
    let manifest_bytes = fs::read(fixture.manifest_path(&oldest)).expect("read oldest manifest");
    let state_directory = fixture.state_directory();

    let error =
        cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
            if step == CleanupStep::BackupQuarantined {
                Err(StorageError::for_test(StorageErrorKind::OperationFailed))
            } else {
                Ok(())
            }
        })
        .expect_err("interrupt after backup quarantine");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    assert!(!fixture.state_root.join(&oldest).exists());
    assert!(fixture.manifest_path(&oldest).is_file());
    let tombstones = cleanup_tombstone_names(&fixture);
    assert_eq!(1, tombstones.len());
    assert!(tombstones[0].ends_with("~backup.tombstone"));
    assert_eq!(
        oldest_bytes,
        fs::read(fixture.state_root.join(&tombstones[0])).expect("read quarantined backup")
    );
    assert_eq!(
        manifest_bytes,
        fs::read(fixture.manifest_path(&oldest)).expect("read canonical manifest")
    );
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );

    cleanup_migration_backups(&fixture.state_root, &state_directory)
        .expect("resume cleanup after first quarantine");
    assert!(cleanup_tombstone_names(&fixture).is_empty());
    assert!(!fixture.state_root.join(&oldest).exists());
    assert!(!fixture.manifest_path(&oldest).exists());
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );
}

#[test]
fn backup_only_recovery_refuses_to_borrow_a_canonical_replacement_manifest() {
    let fixture = BackupFixture::new(3);
    let oldest = fixture.backup_file_names[0].clone();
    let manifest_bytes = fs::read(fixture.manifest_path(&oldest)).expect("read oldest manifest");
    let state_directory = fixture.state_directory();

    cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
        if step == CleanupStep::BackupQuarantined {
            Err(StorageError::for_test(StorageErrorKind::OperationFailed))
        } else {
            Ok(())
        }
    })
    .expect_err("interrupt with backup-only tombstone");
    let backup_tombstone = cleanup_tombstone_names(&fixture)
        .into_iter()
        .find(|name| name.ends_with("~backup.tombstone"))
        .expect("backup-only tombstone");
    let replacement_bytes =
        fs::read(fixture.state_root.join(&backup_tombstone)).expect("read tombstoned backup");
    write_private_file(&fixture.state_root.join(&oldest), &replacement_bytes);
    validate_migration_backup(&fixture.state_root, &state_directory, &oldest)
        .expect("identity-distinct canonical replacement pair is valid");

    let error = cleanup_migration_backups(&fixture.state_root, &state_directory)
        .expect_err("refuse to consume replacement manifest");

    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    assert_eq!(
        replacement_bytes,
        fs::read(fixture.state_root.join(&oldest)).expect("read preserved replacement backup")
    );
    assert_eq!(
        manifest_bytes,
        fs::read(fixture.manifest_path(&oldest)).expect("read preserved replacement manifest")
    );
    assert!(fixture.state_root.join(backup_tombstone).is_file());
    validate_migration_backup(&fixture.state_root, &state_directory, &oldest)
        .expect("replacement pair remains independently valid");
}

#[test]
fn cleanup_first_delete_failure_keeps_a_retryable_quarantined_pair() {
    let fixture = BackupFixture::new(3);
    let oldest = fixture.backup_file_names[0].clone();
    let oldest_bytes = fs::read(fixture.state_root.join(&oldest)).expect("read oldest backup");
    let manifest_bytes = fs::read(fixture.manifest_path(&oldest)).expect("read oldest manifest");
    let state_directory = fixture.state_directory();

    let error =
        cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
            if step == CleanupStep::BeforeBackupDelete {
                Err(StorageError::for_test(StorageErrorKind::OperationFailed))
            } else {
                Ok(())
            }
        })
        .expect_err("fail before deleting quarantined backup");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    let tombstones = cleanup_tombstone_names(&fixture);
    assert_eq!(2, tombstones.len());
    let backup_tombstone = tombstones
        .iter()
        .find(|name| name.ends_with("~backup.tombstone"))
        .expect("backup tombstone name");
    let manifest_tombstone = tombstones
        .iter()
        .find(|name| name.ends_with("~manifest.tombstone"))
        .expect("manifest tombstone name");
    assert_eq!(
        oldest_bytes,
        fs::read(fixture.state_root.join(backup_tombstone)).expect("read quarantined backup")
    );
    assert_eq!(
        manifest_bytes,
        fs::read(fixture.state_root.join(manifest_tombstone)).expect("read quarantined manifest")
    );
    assert!(!fixture.state_root.join(&oldest).exists());
    assert!(!fixture.manifest_path(&oldest).exists());
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );

    cleanup_migration_backups(&fixture.state_root, &state_directory)
        .expect("retry quarantined pair deletion");
    assert!(cleanup_tombstone_names(&fixture).is_empty());
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );
}

#[test]
fn cleanup_second_delete_failure_leaves_only_a_verified_manifest_tombstone_for_retry() {
    let fixture = BackupFixture::new(3);
    let oldest = fixture.backup_file_names[0].clone();
    let manifest_bytes = fs::read(fixture.manifest_path(&oldest)).expect("read oldest manifest");
    let state_directory = fixture.state_directory();

    let error =
        cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
            if step == CleanupStep::BeforeManifestDelete {
                Err(StorageError::for_test(StorageErrorKind::OperationFailed))
            } else {
                Ok(())
            }
        })
        .expect_err("fail before deleting quarantined manifest");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    let tombstones = cleanup_tombstone_names(&fixture);
    assert_eq!(1, tombstones.len());
    assert!(tombstones[0].ends_with("~manifest.tombstone"));
    assert_eq!(
        manifest_bytes,
        fs::read(fixture.state_root.join(&tombstones[0]))
            .expect("read verified manifest tombstone")
    );
    assert!(!fixture.state_root.join(&oldest).exists());
    assert!(!fixture.manifest_path(&oldest).exists());
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );

    cleanup_migration_backups(&fixture.state_root, &state_directory)
        .expect("retry manifest tombstone deletion");
    assert!(cleanup_tombstone_names(&fixture).is_empty());
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );
}

#[test]
fn cleanup_retry_recovers_an_asymmetric_durable_deleting_state() {
    let fixture = BackupFixture::new(3);
    let oldest = fixture.backup_file_names[0].clone();
    let oldest_bytes = fs::read(fixture.state_root.join(&oldest)).expect("read oldest backup");
    let state_directory = fixture.state_directory();

    let error =
        cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
            if step == CleanupStep::BackupDeleteCommitted {
                Err(StorageError::for_test(StorageErrorKind::OperationFailed))
            } else {
                Ok(())
            }
        })
        .expect_err("interrupt after durable backup delete commit");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    let deleting_name = existing_files(&fixture.state_root)
        .into_iter()
        .find(|name| name.ends_with("~backup.deleting"))
        .expect("durable backup deleting name");
    assert_eq!(
        oldest_bytes,
        fs::read(fixture.state_root.join(&deleting_name)).expect("read committed deleting backup")
    );
    assert!(
        cleanup_tombstone_names(&fixture)
            .iter()
            .any(|name| name.ends_with("~manifest.tombstone"))
    );

    cleanup_migration_backups(&fixture.state_root, &state_directory)
        .expect("retry asymmetric deleting state");
    assert!(!fixture.state_root.join(deleting_name).exists());
    assert!(cleanup_tombstone_names(&fixture).is_empty());
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );
}

#[cfg(windows)]
#[test]
fn windows_write_through_move_is_no_clobber_on_real_files() {
    let fixture = BackupFixture::new(1);
    let source_name = "windows-move-source.tmp";
    let destination_name = "windows-move-destination.tmp";
    write_private_file(&fixture.state_root.join(source_name), b"source bytes");
    write_private_file(
        &fixture.state_root.join(destination_name),
        b"destination bytes",
    );
    let state_directory = fixture.state_directory();

    assert_eq!(
        StorageErrorKind::StateConflict,
        state_directory
            .move_leaf(source_name, destination_name)
            .expect_err("write-through move must not replace destination")
            .kind()
    );
    assert_eq!(
        b"source bytes".as_slice(),
        fs::read(fixture.state_root.join(source_name))
            .expect("read retained source")
            .as_slice()
    );
    assert_eq!(
        b"destination bytes".as_slice(),
        fs::read(fixture.state_root.join(destination_name))
            .expect("read retained destination")
            .as_slice()
    );
}

#[cfg(windows)]
#[test]
fn windows_cleanup_uses_real_write_through_and_handle_delete_primitives() {
    let fixture = BackupFixture::new(3);
    let state_directory = fixture.state_directory();
    let mut deleting_names = Vec::new();

    let removed =
        cleanup_migration_backups_with_hook(&fixture.state_root, &state_directory, |step| {
            if matches!(
                step,
                CleanupStep::BackupDeleteCommitted | CleanupStep::ManifestDeleteCommitted
            ) {
                deleting_names.extend(
                    existing_files(&fixture.state_root)
                        .into_iter()
                        .filter(|name| name.ends_with(".deleting")),
                );
            }
            Ok(())
        })
        .unwrap_or_else(|error| {
            panic!(
                "run Windows cleanup primitives: {error:?}; source: {:?}",
                std::error::Error::source(&error)
            )
        });

    assert_eq!(vec![fixture.backup_file_names[0].clone()], removed);
    assert_eq!(2, deleting_names.len());
    assert!(deleting_names[0].ends_with("~backup.deleting"));
    assert!(deleting_names[1].ends_with("~manifest.deleting"));
    assert!(
        !deleting_names
            .iter()
            .any(|name| name.contains(".deleting~"))
    );
    assert!(
        !existing_files(&fixture.state_root)
            .iter()
            .any(|name| name.starts_with("satelle.sqlite3.cleanup~"))
    );
    assert_eq!(
        fixture.backup_file_names[1..].to_vec(),
        validated_backup_names(&fixture)
    );
}

#[cfg(windows)]
#[test]
fn windows_handle_delete_unlinks_before_share_delete_handles_close() {
    let fixture = BackupFixture::new(1);
    let file_name = "windows-handle-delete.tmp";
    write_private_file(&fixture.state_root.join(file_name), b"pinned bytes");
    let state_directory = fixture.state_directory();
    let pinned_file = open_private_leaf(
        &state_directory,
        file_name,
        LeafOpenMode::Existing,
        StorageErrorKind::OperationFailed,
    )
    .expect("open share-delete handle")
    .expect("share-delete handle exists");
    let identity = leaf_identity(&pinned_file, StorageErrorKind::OperationFailed)
        .expect("read pinned identity");

    assert!(
        state_directory
            .delete_leaf(file_name, identity)
            .expect("delete by verified handle")
    );
    assert!(
        !fixture.state_root.join(file_name).exists(),
        "successful cleanup deletion must unlink the namespace entry immediately"
    );
    assert_eq!(
        identity,
        leaf_identity(&pinned_file, StorageErrorKind::OperationFailed)
            .expect("the already-open file object remains pinned")
    );
}

#[test]
fn cleanup_ignores_malformed_lookalikes_without_deleting_them() {
    let fixture = BackupFixture::new(3);
    let malformed_name = "satelle.sqlite3.migration-v8-not-a-uuid.backup";
    let invalid_name = "satelle.sqlite3.migration-v8-ffffffff-ffff-7fff-bfff-ffffffffffff.backup";
    let cleanup_lookalikes = [
        "satelle.sqlite3.cleanup~8~0198a146-5ec2-7dd5-b51c-7d5e241e5896~0198a146-5ec2-7dd5-b51c-7d5e241e5897~00000000000000000000000000000000~11111111111111111111111111111111~backup.tombstone",
        "satelle.sqlite3.cleanup~8~0198a146-5ec2-7dd5-b51c-7d5e241e5896~0198a146-5ec2-7dd5-b51c-7d5e241e5897~00000000000000000000000000000000~11111111111111111111111111111111~manifest.tombstone",
    ];
    write_private_file(&fixture.state_root.join(malformed_name), b"lookalike");
    write_private_file(&fixture.state_root.join(invalid_name), b"not sqlite");
    write_private_file(
        &fixture.state_root.join(format!("{invalid_name}.json")),
        b"{}\n",
    );
    for cleanup_lookalike in cleanup_lookalikes {
        write_private_file(
            &fixture.state_root.join(cleanup_lookalike),
            b"malformed cleanup lookalike",
        );
    }
    let state_directory = fixture.state_directory();

    cleanup_migration_backups(&fixture.state_root, &state_directory)
        .expect("clean up old valid backups");

    assert_eq!(
        b"lookalike".as_slice(),
        fs::read(fixture.state_root.join(malformed_name)).expect("read lookalike")
    );
    assert_eq!(
        b"not sqlite".as_slice(),
        fs::read(fixture.state_root.join(invalid_name)).expect("read invalid backup")
    );
    assert!(
        fixture
            .state_root
            .join(format!("{invalid_name}.json"))
            .is_file()
    );
    for cleanup_lookalike in cleanup_lookalikes {
        assert_eq!(
            b"malformed cleanup lookalike".as_slice(),
            fs::read(fixture.state_root.join(cleanup_lookalike))
                .expect("read preserved cleanup lookalike")
        );
    }
}
