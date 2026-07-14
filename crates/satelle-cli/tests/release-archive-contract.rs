use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::error::Error;
use std::io::{Cursor, Write};
use std::path::Path;
use tar::{Archive, Builder, EntryType, Header};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::FileOptions};

type TestResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, Debug)]
enum ArchiveFormat {
    TarGz,
    Zip,
}

#[derive(Clone, Copy)]
enum FixtureEntry<'a> {
    Regular(&'a str),
    Symlink(&'a str),
}

impl ArchiveFormat {
    fn build(self, entries: &[FixtureEntry<'_>]) -> TestResult<Vec<u8>> {
        match self {
            Self::TarGz => build_tar_gz(entries),
            Self::Zip => build_zip(entries, CompressionMethod::Stored),
        }
    }

    fn has_one_root_regular_file(self, bytes: &[u8], expected: &str) -> TestResult<bool> {
        match self {
            Self::TarGz => tar_gz_has_one_root_regular_file(bytes, expected),
            Self::Zip => zip_has_one_root_regular_file(bytes, expected),
        }
    }
}

fn build_tar_gz(entries: &[FixtureEntry<'_>]) -> TestResult<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::fast());
    let mut archive = Builder::new(encoder);

    for entry in entries {
        let mut header = Header::new_gnu();
        header.set_mode(0o644);

        match entry {
            FixtureEntry::Regular(path) => {
                let contents = format!("fixture for {path}\n");
                header.set_entry_type(EntryType::Regular);
                header.set_size(contents.len() as u64);
                header.set_cksum();
                archive.append_data(&mut header, path, contents.as_bytes())?;
            }
            FixtureEntry::Symlink(path) => {
                header.set_entry_type(EntryType::Symlink);
                header.set_size(0);
                header.set_link_name("target")?;
                header.set_cksum();
                archive.append_data(&mut header, path, std::io::empty())?;
            }
        }
    }

    Ok(archive.into_inner()?.finish()?)
}

fn build_zip(entries: &[FixtureEntry<'_>], compression: CompressionMethod) -> TestResult<Vec<u8>> {
    let mut archive = ZipWriter::new(Cursor::new(Vec::new()));
    let options = FileOptions::default().compression_method(compression);

    for entry in entries {
        match entry {
            FixtureEntry::Regular(path) => {
                archive.start_file(*path, options)?;
                archive.write_all(format!("fixture for {path}\n").as_bytes())?;
            }
            FixtureEntry::Symlink(path) => archive.add_symlink(*path, "target", options)?,
        }
    }

    Ok(archive.finish()?.into_inner())
}

fn tar_gz_has_one_root_regular_file(bytes: &[u8], expected: &str) -> TestResult<bool> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = Archive::new(decoder);
    let mut matches = 0;

    for entry in archive.entries()? {
        let entry = entry?;
        if entry.header().entry_type().is_file() && entry.path()?.as_ref() == Path::new(expected) {
            matches += 1;
        }
    }

    Ok(matches == 1)
}

fn zip_has_one_root_regular_file(bytes: &[u8], expected: &str) -> TestResult<bool> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    let mut matches = 0;

    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index)?;
        let entry_type = entry.unix_mode().map(|mode| mode & 0o170000);
        let is_regular = !entry.is_dir() && matches!(entry_type, None | Some(0 | 0o100000));

        if is_regular && entry.name() == expected {
            matches += 1;
        }
    }

    Ok(matches == 1)
}

fn assert_contract_case(
    format: ArchiveFormat,
    expected: &str,
    entries: &[FixtureEntry<'_>],
    should_pass: bool,
    case: &str,
) {
    let archive = format
        .build(entries)
        .expect("fixture archive should be created");
    let actual = format
        .has_one_root_regular_file(&archive, expected)
        .expect("fixture archive should be readable");

    assert_eq!(
        actual, should_pass,
        "{format:?} archive contract result differed for {case}"
    );
}

#[test]
fn release_archives_require_one_expected_root_executable() {
    for (format, executable) in [
        (ArchiveFormat::TarGz, "satelle"),
        (ArchiveFormat::Zip, "satelle.exe"),
    ] {
        let nested = format!("bin/{executable}");

        for (case, entries, should_pass) in [
            (
                "one root executable with unrelated extras",
                vec![
                    FixtureEntry::Regular(executable),
                    FixtureEntry::Regular("README.txt"),
                    FixtureEntry::Regular("docs/guide.txt"),
                ],
                true,
            ),
            ("missing executable", vec![], false),
            (
                "wrong executable name",
                vec![FixtureEntry::Regular("satelle-wrong")],
                false,
            ),
            (
                "nested executable only",
                vec![FixtureEntry::Regular(nested.as_str())],
                false,
            ),
            (
                "duplicate root executable",
                vec![
                    FixtureEntry::Regular(executable),
                    FixtureEntry::Regular(executable),
                ],
                false,
            ),
            (
                "expected root name is a symlink",
                vec![FixtureEntry::Symlink(executable)],
                false,
            ),
        ] {
            assert_contract_case(format, executable, &entries, should_pass, case);
        }
    }

    let deflated_zip = build_zip(
        &[FixtureEntry::Regular("satelle.exe")],
        CompressionMethod::Deflated,
    )
    .expect("Deflated ZIP fixture should be created");
    assert!(
        zip_has_one_root_regular_file(&deflated_zip, "satelle.exe")
            .expect("Deflated ZIP fixture should be readable"),
        "Deflated ZIP archive should satisfy the root executable contract"
    );
}
