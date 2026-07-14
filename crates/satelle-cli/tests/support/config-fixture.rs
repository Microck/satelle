use assert_cmd::Command;
use satelle_host::test_support::TestStateDir;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[path = "test-file.rs"]
mod test_file;

const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

pub struct ConfigFixture {
    _temp: TempDir,
    project: PathBuf,
    state: TestStateDir,
    user_config: PathBuf,
}

impl ConfigFixture {
    pub fn new(user_config: &str, project_config: &str) -> Self {
        let temp = tempfile::tempdir().expect("temporary directory should be created");
        let project = temp.path().join("project");
        let state = TestStateDir::new().expect("secure state directory should be created");
        let user_config_path = temp.path().join("user-config.toml");
        let project_config_path = project.join(".satelle").join("config.toml");

        fs::create_dir_all(
            project_config_path
                .parent()
                .expect("project config should have a parent"),
        )
        .expect("project config directory should be created");
        test_file::write_user_controlled(&user_config_path, user_config)
            .expect("user config should be written securely");
        fs::write(project_config_path, project_config).expect("project config should be written");

        Self {
            _temp: temp,
            project,
            state,
            user_config: user_config_path,
        }
    }

    pub fn command(&self) -> Command {
        let mut command = Command::cargo_bin("satelle").expect("satelle binary should build");
        for name in [
            "SATELLE_HOME",
            "SATELLE_CONFIG_FILE",
            "SATELLE_STATE_DIR",
            "SATELLE_CACHE_DIR",
            "SATELLE_LOG_DIR",
            "SATELLE_HOST",
            "SATELLE_PROFILE",
            TEST_SUPPORT_ADAPTER_ENV,
        ] {
            command.env_remove(name);
        }
        command
            .current_dir(&self.project)
            .env("SATELLE_CONFIG_FILE", &self.user_config)
            .env("SATELLE_STATE_DIR", self.state.path())
            .env(TEST_SUPPORT_ADAPTER_ENV, "fake");
        command
    }

    pub fn write_project_config(&self, config: &str) {
        fs::write(self.project.join(".satelle").join("config.toml"), config)
            .expect("project config should be replaced");
    }

    pub fn write_user_config(&self, config: &str) {
        test_file::write_user_controlled(&self.user_config, config)
            .expect("user config should be replaced securely");
    }

    pub fn user_config_path(&self) -> &Path {
        &self.user_config
    }

    pub fn resolved_project_config(&self) -> PathBuf {
        self.project
            .canonicalize()
            .expect("project fixture path should resolve")
            .join(".satelle")
            .join("config.toml")
    }
}

pub fn parse_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("output should be one JSON value")
}

pub fn assert_same_file(actual: &Value, expected: &Path) -> String {
    let actual = actual
        .as_str()
        .expect("file detail should be a path string");
    assert_eq!(
        Path::new(actual)
            .canonicalize()
            .expect("reported file should resolve"),
        expected
            .canonicalize()
            .expect("expected file should resolve")
    );
    actual.to_owned()
}
