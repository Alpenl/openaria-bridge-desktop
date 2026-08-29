use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use uuid::Uuid;
use ylx_transfer_core::persistence::transfer_store::performance::{
    BenchmarkConfig, Score32BenchmarkFixture,
};

const HELP: &str = "\
Deterministic OpenAria Desktop session-refresh performance gate

Usage:
  session-refresh-benchmark [OPTIONS]

Options:
  --warmup <COUNT>         Warm-up samples [default: 2]
  --samples <COUNT>        Measured samples; must be greater than zero [default: 11]
  --output <PATH>          JSON report path [default: performance-results/session-refresh.json]
  --source-commit <SHA>    Exact 40-character lowercase Git commit (uses GITHUB_SHA by default)
  -h, --help               Print help
";

struct CliArgs {
    config: BenchmarkConfig,
    output: PathBuf,
    source_commit: Option<String>,
}

enum CliAction {
    Run(CliArgs),
    Help,
}

fn main() -> ExitCode {
    match execute() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("session refresh performance regression gate failed");
            ExitCode::from(3)
        }
        Err(error) => {
            eprintln!("session refresh benchmark failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn execute() -> Result<bool, String> {
    let args = match parse_args(env::args_os().skip(1))? {
        CliAction::Run(args) => args,
        CliAction::Help => {
            print!("{HELP}");
            return Ok(true);
        }
    };

    let database = TemporaryDatabase::new();
    let mut report = {
        let fixture = Score32BenchmarkFixture::create(database.path().to_path_buf())
            .map_err(|error| error.to_string())?;
        fixture
            .run(args.config)
            .map_err(|error| error.to_string())?
    };
    report.source_commit = args.source_commit;

    let mut json = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    json.push(b'\n');
    if let Some(parent) = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "could not create report directory {}: {error}",
                parent.display()
            )
        })?;
    }
    std::fs::write(&args.output, &json)
        .map_err(|error| format!("could not write report {}: {error}", args.output.display()))?;
    io::stdout()
        .lock()
        .write_all(&json)
        .map_err(|error| format!("could not write report to stdout: {error}"))?;

    Ok(report.gate.passed)
}

fn parse_args(arguments: impl IntoIterator<Item = OsString>) -> Result<CliAction, String> {
    let defaults = BenchmarkConfig::default();
    let mut warmup_samples = defaults.warmup_samples;
    let mut measured_samples = defaults.measured_samples;
    let mut output = PathBuf::from("performance-results/session-refresh.json");
    let mut source_commit = None;
    let mut arguments = arguments.into_iter();

    while let Some(argument) = arguments.next() {
        let flag = argument
            .to_str()
            .ok_or_else(|| format!("argument is not valid UTF-8: {argument:?}"))?;
        match flag {
            "-h" | "--help" => return Ok(CliAction::Help),
            "--warmup" => {
                warmup_samples = parse_count(next_value(&mut arguments, flag)?, flag)?;
            }
            "--samples" => {
                measured_samples = parse_count(next_value(&mut arguments, flag)?, flag)?;
            }
            "--output" => output = PathBuf::from(next_value(&mut arguments, flag)?),
            "--source-commit" => {
                source_commit = Some(parse_commit(next_value(&mut arguments, flag)?, flag)?);
            }
            _ => return Err(format!("unknown argument {flag:?}; use --help for usage")),
        }
    }

    if measured_samples == 0 {
        return Err("--samples must be greater than zero".to_string());
    }
    if source_commit.is_none() {
        source_commit = env::var_os("GITHUB_SHA")
            .map(|value| parse_commit(value, "GITHUB_SHA"))
            .transpose()?;
    }

    Ok(CliAction::Run(CliArgs {
        config: BenchmarkConfig {
            warmup_samples,
            measured_samples,
        },
        output,
        source_commit,
    }))
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<OsString, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_count(value: OsString, flag: &str) -> Result<usize, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{flag} value is not valid UTF-8"))?
        .parse()
        .map_err(|_| format!("{flag} requires a non-negative integer"))
}

fn parse_commit(value: OsString, source: &str) -> Result<String, String> {
    let value = value
        .into_string()
        .map_err(|_| format!("{source} value is not valid UTF-8"))?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{source} must be an exact 40-character lowercase Git SHA"
        ));
    }
    Ok(value)
}

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new() -> Self {
        Self {
            path: env::temp_dir().join(format!("openaria-score-32-{}.sqlite3", Uuid::new_v4())),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.path.as_os_str().to_os_string();
            path.push(suffix);
            match std::fs::remove_file(PathBuf::from(path)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    eprintln!("warning: could not remove benchmark database sidecar: {error}")
                }
            }
        }
    }
}
