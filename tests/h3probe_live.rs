//! Opt-in qualification for the operator-built h3probe driver.
//!
//! Set `WINDBG_MCP_SMOKE_H3PROBE` to a private JSON config and run this test alone. The config
//! names one explicitly disposable VM, the service, a typed GPA corpus, one reserved write byte,
//! and commands which restart and health-check that exact VM. The server never runs those commands;
//! this test is the operator-requested qualification harness.

use std::io::{BufRead, BufReader};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    disposable: bool,
    vm_id: String,
    profile: String,
    service: String,
    vp: u32,
    corpus: Vec<Corpus>,
    write: WriteTarget,
    restart_command: Vec<String>,
    health_command: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    gpa: String,
    result: String,
    range: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteTarget {
    gpa: String,
    offset: u16,
}

#[derive(Clone)]
struct Identity {
    vmwp_pid: u64,
    partition_handle: String,
    partition_id: String,
}

fn executable() -> String {
    std::env::var("CARGO_BIN_EXE_windbg-mcp").expect("Cargo did not provide the windbg-mcp binary")
}

fn run(words: &[String]) -> Output {
    assert!(!words.is_empty(), "a configured command may not be empty");
    Command::new(&words[0])
        .args(&words[1..])
        .output()
        .unwrap_or_else(|error| panic!("launching {words:?}: {error}"))
}

fn succeeded(words: &[String], what: &str) -> Output {
    let output = run(words);
    assert!(
        output.status.success(),
        "{what} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn discovery(config: &Config) -> Identity {
    let output = succeeded(
        &[
            executable(),
            "--sk-discover-identity".into(),
            "--profile".into(),
            config.profile.clone(),
            "--vm-id".into(),
            config.vm_id.clone(),
        ],
        "identity discovery",
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("discovery returned JSON");
    Identity {
        vmwp_pid: value["vmwp_pid"].as_u64().expect("vmwp_pid is unsigned"),
        partition_handle: value["partition_handle"]
            .as_str()
            .expect("partition_handle is hexadecimal")
            .into(),
        partition_id: value["partition_id"]
            .as_str()
            .expect("partition_id is hexadecimal")
            .into(),
    }
}

fn qualification_command(
    config: &Config,
    identity: &Identity,
    concurrency: usize,
    iterations: usize,
    write: bool,
) -> Vec<String> {
    let mut command = vec![
        executable(),
        "--sk-h3-qualify".into(),
        "--vmwp-pid".into(),
        identity.vmwp_pid.to_string(),
        "--partition-handle".into(),
        identity.partition_handle.clone(),
        "--partition-id".into(),
        identity.partition_id.clone(),
        "--vp".into(),
        config.vp.to_string(),
        "--concurrency".into(),
        concurrency.to_string(),
        "--iterations".into(),
        iterations.to_string(),
    ];
    for row in &config.corpus {
        command.extend(["--gpa".into(), row.gpa.clone()]);
    }
    if write {
        command.extend([
            "--write-gpa".into(),
            config.write.gpa.clone(),
            "--write-offset".into(),
            config.write.offset.to_string(),
        ]);
    }
    command
}

fn qualify(config: &Config, identity: &Identity) -> Value {
    let output = succeeded(
        &qualification_command(config, identity, 8, 100, true),
        "h3probe qualification",
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("qualification returned JSON");
    assert_eq!(value["result"], "pass");
    assert_eq!(value["unknown_ioctl_rejected"], true);
    assert_eq!(value["write"]["restored"], true);
    for (expected, actual) in config.corpus.iter().zip(
        value["corpus"]
            .as_array()
            .expect("qualification corpus is an array"),
    ) {
        assert_eq!(actual["memory"]["result"], expected.result);
        assert_eq!(actual["translation"]["kind"], expected.range);
    }
    value
}

fn concurrent_processes(config: &Config, identity: &Identity) {
    thread::scope(|scope| {
        let mut readers = Vec::new();
        for _ in 0..8 {
            readers.push(scope.spawn(|| {
                succeeded(
                    &qualification_command(config, identity, 1, 100, false),
                    "concurrent h3probe reader process",
                );
            }));
        }
        for reader in readers {
            reader.join().expect("concurrent reader process panicked");
        }
    });
}

fn kill_memory_provider(config: &Config, identity: &Identity) {
    let mut child = Command::new(executable())
        .args([
            "--sk-h3-memory",
            "--vmwp-pid",
            &identity.vmwp_pid.to_string(),
            "--partition-handle",
            &identity.partition_handle,
            "--partition-id",
            &identity.partition_id,
            "--vp",
            &config.vp.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start memory provider");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("provider stdout"))
        .read_line(&mut ready)
        .expect("read provider ready line");
    assert_eq!(ready.trim(), "windbg-mcp-gpa/1");
    child.kill().expect("kill provider child");
    assert!(!child.wait().expect("reap provider").success());
}

struct ServiceGuard(String);

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        let _ = Command::new("sc.exe").args(["start", &self.0]).output();
    }
}

fn service_stop_under_load(config: &Config, identity: &Identity) {
    let _guard = ServiceGuard(config.service.clone());
    let command = qualification_command(config, identity, 64, 10_000, false);
    let mut load = Command::new(&command[0])
        .args(&command[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start qualification load");
    thread::sleep(Duration::from_millis(100));
    assert!(
        load.try_wait().expect("query load").is_none(),
        "load ended before service stop"
    );
    let stop = Command::new("sc.exe")
        .args(["stop", &config.service])
        .output()
        .expect("request service stop");
    assert!(
        stop.status.success(),
        "sc stop failed: {}",
        String::from_utf8_lossy(&stop.stdout)
    );
    load.kill().expect("kill load holder");
    let _ = load.wait();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let query = Command::new("sc.exe")
            .args(["query", &config.service])
            .output()
            .expect("query service");
        let text = String::from_utf8_lossy(&query.stdout);
        if text.contains("STOPPED") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "service did not stop after killed holder: {text}"
        );
        thread::sleep(Duration::from_millis(200));
    }
    succeeded(
        &["sc.exe".into(), "start".into(), config.service.clone()],
        "service restart",
    );
}

fn stale_identity_after_restart(config: &Config, old: &Identity) -> Identity {
    succeeded(&config.restart_command, "disposable VM restart");
    succeeded(&config.health_command, "post-restart health check");
    let stale = run(&qualification_command(config, old, 8, 100, false));
    assert!(
        !stale.status.success(),
        "pre-restart vmwp coordinates were accepted"
    );
    let fresh = discovery(config);
    assert_ne!(
        fresh.vmwp_pid, old.vmwp_pid,
        "restart retained the vmwp identity"
    );
    fresh
}

#[test]
#[ignore = "controls an explicitly disposable VM and h3probe service; set WINDBG_MCP_SMOKE_H3PROBE"]
fn h3probe_driver_qualifies_on_a_disposable_vm() {
    let Some(path) = std::env::var_os("WINDBG_MCP_SMOKE_H3PROBE") else {
        eprintln!("set WINDBG_MCP_SMOKE_H3PROBE=<private JSON config>");
        return;
    };
    let config: Config = serde_json::from_slice(&std::fs::read(path).expect("read config"))
        .expect("parse h3probe config");
    assert!(
        config.disposable,
        "the h3probe tier requires disposable: true"
    );
    assert!(
        !config.corpus.is_empty(),
        "the h3probe tier requires a corpus"
    );
    assert!(!config.restart_command.is_empty() && !config.health_command.is_empty());

    let first = discovery(&config);
    qualify(&config, &first);
    concurrent_processes(&config, &first);
    kill_memory_provider(&config, &first);
    qualify(&config, &first);
    service_stop_under_load(&config, &first);
    let fresh = stale_identity_after_restart(&config, &first);
    qualify(&config, &fresh);
}
