use super::{
    CliFailure, SkillNameCommand, SkillsCommand, SkillsOutputCommand, failure, print_json,
};
use satelle_core::{ErrorCode, SatelleError, resolve_path_set};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const BUNDLE_VERSION: &str = env!("CARGO_PKG_VERSION");

struct BundledSkill {
    name: &'static str,
    description: &'static str,
    source: &'static str,
}

const BUNDLED_SKILLS: [BundledSkill; 4] = [
    BundledSkill {
        name: "satelle",
        description: "Route Satelle work to the narrow setup, use, or recover skill.",
        source: include_str!("../../../skills/satelle/SKILL.md"),
    },
    BundledSkill {
        name: "satelle-setup",
        description: "Set up and verify Satelle hosts without hiding consent or secrets.",
        source: include_str!("../../../skills/satelle-setup/SKILL.md"),
    },
    BundledSkill {
        name: "satelle-use",
        description: "Run, steer, inspect, and stop Satelle sessions.",
        source: include_str!("../../../skills/satelle-use/SKILL.md"),
    },
    BundledSkill {
        name: "satelle-recover",
        description: "Recover Satelle failures from typed diagnostics and preserved state.",
        source: include_str!("../../../skills/satelle-recover/SKILL.md"),
    },
];

#[derive(Serialize)]
struct SkillSummary<'a> {
    name: &'a str,
    description: &'a str,
}

#[derive(Serialize)]
struct SkillListReport<'a> {
    schema_version: &'static str,
    bundle_version: &'static str,
    skills: Vec<SkillSummary<'a>>,
}

#[derive(Serialize)]
struct SkillReport<'a> {
    schema_version: &'static str,
    bundle_version: &'static str,
    name: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct SkillPathReport<'a> {
    schema_version: &'static str,
    bundle_version: &'static str,
    name: &'a str,
    path: String,
}

pub(super) fn run(command: SkillsCommand) -> Result<(), CliFailure> {
    match command {
        SkillsCommand::List(command) => list(command),
        SkillsCommand::Get(command) => get(command),
        SkillsCommand::Path(command) => path(command),
    }
}

fn list(command: SkillsOutputCommand) -> Result<(), CliFailure> {
    let report = SkillListReport {
        schema_version: "satelle.skills.list.v1",
        bundle_version: BUNDLE_VERSION,
        skills: BUNDLED_SKILLS
            .iter()
            .map(|skill| SkillSummary {
                name: skill.name,
                description: skill.description,
            })
            .collect(),
    };
    if command.output_args.requests_json() {
        return print_json(&report).map_err(failure);
    }
    println!("Satelle Agent Skill Bundle {BUNDLE_VERSION}");
    for skill in report.skills {
        println!("{}: {}", skill.name, skill.description);
    }
    Ok(())
}

fn get(command: SkillNameCommand) -> Result<(), CliFailure> {
    let skill = bundled_skill(&command.name)?;
    if command.output_args.requests_json() {
        return print_json(&SkillReport {
            schema_version: "satelle.skills.get.v1",
            bundle_version: BUNDLE_VERSION,
            name: skill.name,
            content: skill.source,
        })
        .map_err(failure);
    }
    println!("Satelle Agent Skill Bundle {BUNDLE_VERSION}");
    print!("{}", skill.source);
    Ok(())
}

fn path(command: SkillNameCommand) -> Result<(), CliFailure> {
    let skill = bundled_skill(&command.name)?;
    let cwd =
        std::env::current_dir().map_err(|error| io_failure("read current directory", error))?;
    let cache_root = resolve_path_set(&cwd).map_err(failure)?.cache_root;
    let path = cache_root
        .join("skills")
        .join(BUNDLE_VERSION)
        .join(skill.name)
        .join("SKILL.md");
    materialize(&path, skill.source.as_bytes())?;
    if command.output_args.requests_json() {
        return print_json(&SkillPathReport {
            schema_version: "satelle.skills.path.v1",
            bundle_version: BUNDLE_VERSION,
            name: skill.name,
            path: path.display().to_string(),
        })
        .map_err(failure);
    }
    println!("{}", path.display());
    Ok(())
}

fn bundled_skill(name: &str) -> Result<&'static BundledSkill, CliFailure> {
    BUNDLED_SKILLS
        .iter()
        .find(|skill| skill.name == name)
        .ok_or_else(|| {
            let mut error = SatelleError::invalid_usage(format!("unknown bundled skill '{name}'"));
            error.details.insert(
                "available_skills".to_string(),
                serde_json::json!(
                    BUNDLED_SKILLS
                        .iter()
                        .map(|skill| skill.name)
                        .collect::<Vec<_>>()
                ),
            );
            failure(error)
        })
}

fn materialize(path: &Path, source: &[u8]) -> Result<(), CliFailure> {
    if path.exists() {
        return validate_materialized(path, source);
    }
    let parent = path.parent().expect("bundled skill path has a parent");
    fs::create_dir_all(parent).map_err(|error| io_failure("create skill cache", error))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| io_failure("create temporary bundled skill", error))?;
    std::io::Write::write_all(&mut temporary, source)
        .map_err(|error| io_failure("write bundled skill", error))?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_materialized(path, source)
        }
        Err(error) => Err(io_failure("publish bundled skill", error.error)),
    }
}

fn validate_materialized(path: &Path, source: &[u8]) -> Result<(), CliFailure> {
    let existing = fs::read(path).map_err(|error| io_failure("read bundled skill", error))?;
    if existing == source {
        return Ok(());
    }
    Err(failure(SatelleError {
        code: ErrorCode::ConfigError,
        message: format!("cached bundled skill is corrupt: {}", path.display()),
        recovery_command: None,
        source_detail: None,
        details: BTreeMap::new(),
    }))
}

fn io_failure(action: &str, error: impl std::fmt::Display) -> CliFailure {
    failure(SatelleError {
        code: ErrorCode::ConfigError,
        message: format!("could not {action}: {error}"),
        recovery_command: None,
        source_detail: None,
        details: BTreeMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;

    #[test]
    fn embedded_bytes_match_release_sources() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for skill in &BUNDLED_SKILLS {
            let source = root.join("skills").join(skill.name).join("SKILL.md");
            assert_eq!(
                fs::read(source).expect("read skill source"),
                skill.source.as_bytes()
            );
            assert!(!skill.source.contains("api_key"));
            assert!(!skill.source.contains("bearer token:"));
        }
    }

    #[test]
    fn every_bundled_command_example_parses_with_this_binary() {
        let mut validated = 0;
        for skill in &BUNDLED_SKILLS {
            for line in skill.source.lines() {
                let fenced = std::iter::once(line.trim());
                let inline = line.split('`').skip(1).step_by(2).map(str::trim);
                for command in fenced
                    .chain(inline)
                    .filter(|text| text.starts_with("satelle "))
                {
                    validated += 1;
                    let arguments = command
                        .strip_prefix("satelle ")
                        .expect("filtered Satelle command");
                    let argv = std::iter::once("satelle").chain(arguments.split_ascii_whitespace());
                    Cli::try_parse_from(argv).unwrap_or_else(|error| {
                        panic!(
                            "{} contains an invalid command example '{command}': {error}",
                            skill.name
                        )
                    });
                }
            }
        }
        assert!(validated > 1, "validate fenced and inline command examples");
    }

    #[test]
    fn concurrent_materialization_of_identical_bytes_is_idempotent() {
        let directory = tempfile::tempdir().expect("temporary skill cache");
        let path = directory.path().join("satelle/SKILL.md");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(32));
        let workers = (0..32)
            .map(|_| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    materialize(&path, b"release-matched skill\n")
                })
            })
            .collect::<Vec<_>>();

        for worker in workers {
            let outcome = worker
                .join()
                .expect("materialization worker should not panic");
            assert!(
                outcome.is_ok(),
                "identical concurrent materialization should succeed"
            );
        }
        assert_eq!(
            fs::read(path).expect("materialized skill"),
            b"release-matched skill\n"
        );
    }
}
