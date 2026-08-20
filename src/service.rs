//! The listener as a Windows service: a debugger that outlives the shell that started it.
//!
//! `--listen` on its own is a foreground process, and that costs three things a debugging host
//! actually needs. It **dies with the login session**, so a reconnecting client finds nothing. It
//! inherits **whatever `PATH` and working directory that shell had**, which for this server is not
//! cosmetic — the engine DLLs beside the exe, and `TTD.exe`, are found or not found by exactly
//! that. And it cannot **start at boot**, so the machine that exists to be debugged is only
//! debuggable once somebody has logged into it.
//!
//! This is the smallest thing that fixes all three: the same `--listen` server, run under the
//! Service Control Manager.
//!
//! ## Stopping is the part that matters
//!
//! For most services a stop is a formality. Here it is the one operation that can damage something
//! outside this process: DbgEng leaves a detached-but-halted kernel **frozen**, so a service that
//! is killed rather than asked holds someone's machine stopped until they notice. So the stop path
//! is the same graceful one a client disconnect takes — every session asked to release its target,
//! then the process exits — and the SCM is told `StopPending` with a wait hint that covers it,
//! rather than being left to assume the default and kill us partway through.
//!
//! That is also why [`crate::listen::serve`] takes a shutdown future at all. Nothing else needs
//! one: under stdio the client's disconnect *is* the signal, and a foreground listener has no way
//! to be asked politely.
//!
//! ## What it cannot do for you
//!
//! A service has no console, so **stderr goes nowhere**. The bounded ring behind `server_log`
//! already answers "what has the server been doing" over the transport, and that is the right
//! channel for it — but it is reachable only once the listener is up, which is exactly not the case
//! worth diagnosing. So the service role also writes its log to a file ([`log_path`]), and a
//! listener that refuses to start says why in there.
//!
//! ## The token cannot live in the machine environment
//!
//! A service has no user environment, and the obvious move — put `WINDBG_MCP_LISTEN_TOKEN` in the
//! *machine* environment — is a **local privilege escalation**, not an inconvenience. The machine
//! environment is readable by every local process including unprivileged ones; the listener is
//! reachable on loopback by the same; and `launch` takes an arbitrary command line and runs it from
//! a worker this service spawned. So any local user who can read that variable can have
//! `LocalSystem`, and the token is the only thing in the way.
//!
//! So [`install`] takes the credentials out of the installing shell's *user* environment, writes
//! them to [`token_file`], strips inheritance and grants read to `SYSTEM` and `Administrators`
//! only, and points the service at it with [`crate::listen::TOKEN_FILE_ENV`]. The property that
//! makes the foreground listener safe — the token is not readable by an unprivileged process — is
//! the one being preserved, by the only mechanism that preserves it once the reader is a service.
//!
//! **Credentials, plural, because a service reads nothing else.** A file shuts the environment out
//! entirely (that is the point of it), so a service-hosted listener holds exactly the clients its
//! file names — and until it could name more than one, the per-client boundary this server has
//! could not be had in the deployment it recommends. The install copies every
//! `WINDBG_MCP_LISTEN_TOKEN*` variable in the shell, and writes the shape that fits: one client
//! named `local` is a bare token, as it always was, and anything else is a JSON object of name to
//! token. Same file, same ACL, same reasoning.
//!
//! The same applies to **kernel connection profiles**, and less obviously, because they are a file
//! rather than a variable: `LocalSystem`'s `%USERPROFILE%` is
//! `C:\Windows\system32\config\systemprofile`, so the `profiles.json` in *your* home is invisible to
//! the service and `attach_kernel {}` running under it lists nothing. Verified rather than assumed.
//! [`install`] says so at the moment an operator is standing there to read it.

use std::ffi::{OsStr, OsString};
use std::net::SocketAddr;
use std::os::windows::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

/// Runs the listener under the SCM. Set by the SCM itself, never typed by hand.
pub const SERVICE_FLAG: &str = "--service";
/// Registers the service. Needs `--listen <addr>` beside it, and an elevated shell.
pub const INSTALL_FLAG: &str = "--install-service";
/// Removes it again.
pub const UNINSTALL_FLAG: &str = "--uninstall-service";
/// Acknowledges installing from a directory Windows does not protect. See [`under_protected_root`].
pub const ALLOW_UNPROTECTED_FLAG: &str = "--allow-unprotected-path";

/// Overrides where the service writes its log.
pub const LOG_ENV: &str = "WINDBG_MCP_SERVICE_LOG";

/// The service's key in the SCM. Also the name `net start` / `sc.exe` take.
const NAME: &str = "windbg-mcp";
const DISPLAY_NAME: &str = "windbg-mcp (WinDbg/DbgEng MCP server)";
const DESCRIPTION: &str = "Serves WinDbg/DbgEng over MCP on an HTTP endpoint for a remote client. \
                           Holds each debug target in its own engine worker process.";

/// A service runs in its own process, so the SCM may stop it on its own account.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// How often the SCM is told the stop is still going.
///
/// A wait hint alone is not enough: the SCM reads *progress* as a rising checkpoint, and a status
/// that never moves is a service it may call hung however generous the hint was.
const CHECKPOINT_EVERY: Duration = Duration::from_secs(5);

/// The longest a stop can legitimately take, which is what the SCM is asked to wait.
///
/// **Derived, not chosen**, because a guessed constant is wrong in the direction that costs a
/// machine. Releasing every worker runs them concurrently against
/// [`crate::engine::SHUTDOWN_RELEASE_TIMEOUT`] — but a session running a `debug_batch` extends its
/// own release by what the batch says it still needs, and `Sessions::release` caps that extension
/// at the configured call timeout. So the real bound is those two added, and on a host with a
/// raised `WINDBG_MCP_CALL_TIMEOUT_SECS` it rises with it.
///
/// Under-asking is the failure that matters: the SCM stops waiting, shutdown proceeds, and a live
/// kernel worker cut off mid-release is a machine left frozen — the exact outcome this lifecycle
/// exists to avoid.
fn stop_bound() -> Duration {
    crate::engine::SHUTDOWN_RELEASE_TIMEOUT + crate::call_timeout() + CHECKPOINT_EVERY
}

/// Which service role, if any, this command line asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The SCM started us.
    Run,
    Install,
    Uninstall,
}

/// Reads the role off the command line. `None` for every ordinary invocation.
///
/// A free function over the arguments, like [`crate::listen::requested`], so the role can be
/// decided before a runtime exists — installing touches the SCM and nothing else, and the service
/// role has to build its runtime *inside* the SCM's own thread rather than around it.
pub fn requested(args: &[String]) -> Option<Role> {
    args.iter().find_map(|arg| match arg.as_str() {
        SERVICE_FLAG => Some(Role::Run),
        INSTALL_FLAG => Some(Role::Install),
        UNINSTALL_FLAG => Some(Role::Uninstall),
        _ => None,
    })
}

/// Where the service logs, since it has no console to log to.
///
/// `%ProgramData%` rather than beside the exe: the service runs as `LocalSystem`, the exe may sit
/// somewhere a service account should not be writing, and an operator looking for a service's log
/// looks there first.
pub fn log_path() -> PathBuf {
    if let Some(path) = std::env::var_os(LOG_ENV) {
        return PathBuf::from(path);
    }
    state_dir().join("service.log")
}

/// Where the service keeps what it needs across a restart: its log, and its token.
///
/// The two derive from *here* rather than from each other, and that is not tidiness. Deriving the
/// token path from the log path — which this did first — means [`LOG_ENV`] silently moves the
/// credential as well: `install` writes the token where the *installing shell* computes, the
/// service looks where the *machine* environment computes, and the two disagree the moment anyone
/// redirects the log. The service then starts, finds no token, and exits with a service-specific
/// error and an empty log file, which is about as unhelpful as a failure gets.
fn state_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("windbg-mcp")
}

/// The command line the SCM will start, as an argument list.
///
/// Built here and asserted on in tests, because the failure it prevents is a service that installs
/// cleanly and then fails at every start: the SCM stores this once, and nothing re-derives it.
fn launch_arguments(addr: SocketAddr) -> Vec<OsString> {
    vec![
        OsString::from(SERVICE_FLAG),
        OsString::from(crate::listen::LISTEN_FLAG),
        OsString::from(addr.to_string()),
    ]
}

/// Where the service reads its bearer token from.
///
/// A file rather than the machine environment, and the difference is a privilege boundary rather
/// than a preference — see the module docs. Beside the log, under `%ProgramData%`, because that is
/// where a `LocalSystem` service's state belongs and an operator knows to look.
pub fn token_file() -> PathBuf {
    state_dir().join("token")
}

/// What goes in [`token_file`]: the credentials from the installing shell, in the shape that fits.
///
/// **One client called `local` is written as a bare token**, which is what this file has always
/// held and what a hand-written one still is — so an upgrade does not rewrite the file of the
/// install everybody has, and an operator comparing it against `$env:WINDBG_MCP_LISTEN_TOKEN` sees
/// the same thing they always did. Anything else is a JSON object of name to token, which is the
/// only shape that can carry more than one and the same one `WINDBG_MCP_PROFILES` uses.
///
/// Both are read back by [`crate::client::TokenFile`], which is where the shapes are defined; this
/// only has to pick between them — and picks by [asking it](reads_back_bare) rather than by
/// restating its rule.
fn token_file_contents(credentials: &[(String, String)]) -> String {
    if let [(name, token)] = credentials
        && name == crate::client::Client::LOCAL
        && reads_back_bare(token)
    {
        return token.clone();
    }
    let named: std::collections::BTreeMap<&str, &str> = credentials
        .iter()
        .map(|(name, token)| (name.as_str(), token.as_str()))
        .collect();
    // Pretty, and a trailing newline: this is a file an operator will open when something is wrong,
    // and `Get-Content` on a single long line is not a way to read one.
    //
    // `expect` rather than a fallback, on a map of strings that cannot fail to serialize: the
    // fallback would be an empty credential file written by an install that reported success, and
    // a service that then refuses every caller — which is the exact outcome this path exists to
    // prevent.
    serde_json::to_string_pretty(&named).expect("a map of strings serializes") + "\n"
}

/// Whether `token`, written on its own, reads back as the one `local` credential it is meant to be.
///
/// **Asked of the reader rather than restated here**, because the bare shape is the reader's to
/// define and this is the second place that would have to know its rules. Review caught the first
/// thing that costs: a random token beginning with `{` is read as the JSON shape, so writing it
/// bare is an install that reports success and a service that fails at every start. It goes in the
/// object instead — the token is not the operator's mistake — and a writer that asks cannot drift
/// from a reader that changes.
///
/// **The question is about the credential, not the name**, and getting that wrong was the second
/// finding: a token that is itself a one-entry object — `{"local":"replacement"}` — parses to a
/// client called `local`, so a check on the name alone said yes and the service would then have
/// accepted `replacement` instead of what the operator set. So: exactly one credential, and it is
/// *this* token naming `local`.
///
/// No filesystem is touched: [`crate::client::TokenFile::parse`] takes the text, and the path is
/// only what its refusals would name.
fn reads_back_bare(token: &str) -> bool {
    crate::client::TokenFile::parse(token, &token_file())
        .and_then(|file| crate::client::Credentials::from_entries(std::iter::empty(), Some(file)))
        .is_ok_and(|creds| {
            creds.len() == 1
                && creds
                    .client_for(token)
                    .is_some_and(|client| client.name() == crate::client::Client::LOCAL)
        })
}

/// `SYSTEM` and `Administrators`, by SID so a localised Windows is not a special case.
const SYSTEM_SID: &str = "*S-1-5-18";
const ADMINISTRATORS_SID: &str = "*S-1-5-32-544";

/// Runs one `icacls` invocation, or says which one failed and why.
fn icacls(path: &std::path::Path, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .with_context(|| format!("cannot run `icacls {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`icacls {} {}` failed: {}",
            path.display(),
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Gives `path` an owner and an ACL that exclude everyone but `SYSTEM` and `Administrators`.
///
/// **Three steps, and none of them is optional**, because `%ProgramData%` lets any local user
/// create things there and keep them:
///
/// 1. `/setowner`. An owner has implicit `WRITE_DAC` — it can rewrite whatever ACL we set,
///    whenever it likes — so leaving a squatter as owner makes the rest of this decorative.
/// 2. `/reset`. `/inheritance:r` removes only *inherited* ACEs, and `/grant:r` replaces grants
///    only for the principals it names. An explicit ACE a squatter put there survives both. This
///    is what clears it.
/// 3. `/inheritance:r` with the two grants, which is then the whole of the ACL.
///
/// Shelling out to `icacls` rather than calling `SetNamedSecurityInfo`: this runs once, at install,
/// in an elevated shell, and each command is one an operator can read, re-run and verify by hand —
/// which for the object that *is* the security boundary is worth more than avoiding a process spawn.
fn restrict_to_administrators(path: &std::path::Path, rights: &str) -> Result<()> {
    icacls(path, &["/setowner", ADMINISTRATORS_SID, "/c"])?;
    icacls(path, &["/reset", "/c"])?;
    icacls(
        path,
        &[
            "/inheritance:r",
            "/grant:r",
            &format!("{SYSTEM_SID}:({rights})"),
            "/grant:r",
            &format!("{ADMINISTRATORS_SID}:({rights})"),
        ],
    )
}

/// The state directory, created and locked down before anything is written into it.
///
/// Securing the *directory* matters as much as the file: an unprivileged user who pre-creates
/// `%ProgramData%\windbg-mcp` owns it, and can then delete or replace whatever we put inside. A
/// reparse point is refused outright rather than followed, since a junction planted there would
/// have us write the credential wherever its author chose.
fn secured_state_dir() -> Result<PathBuf> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let meta = std::fs::symlink_metadata(&dir)
        .with_context(|| format!("cannot inspect {}", dir.display()))?;
    // **Not `is_symlink()`.** On Windows that recognises symbolic links and *not* directory
    // junctions, which carry a different reparse tag and are the ones an unprivileged user can
    // create without any privilege at all. Testing the attribute catches every reparse tag there
    // is, which is the only safe reading of "is this really the directory I asked for".
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "{} is a reparse point (a junction or a symlink). Refusing to write the service's \
             token through it, since where it leads is not this installer's to trust — remove it \
             and install again.",
            dir.display()
        );
    }
    restrict_to_administrators(&dir, "F")?;
    Ok(dir)
}

/// Whether `exe` sits somewhere only administrators can write.
///
/// The roots Windows protects by default, and nothing clever: `%ProgramFiles%`,
/// `%ProgramFiles(x86)%` and `%SystemRoot%`. Anywhere else — a checkout, a `target\debug`, a
/// download folder — is writable by whoever owns it, and the SCM stores an **exact path** for a
/// `LocalSystem` auto-start service. Its owner can then replace the exe, or an engine DLL beside
/// it, and have their code loaded as SYSTEM at the next start. That is the classic weak-service-
/// binary escalation, and the install is where it is cheap to refuse.
///
/// A root list rather than an ACL inspection on purpose. Reading the effective rights of every
/// unprivileged principal against a path is the *correct* test and a fragile one — locale-dependent
/// output, inherited and denied ACEs, group nesting — and a security check that is sometimes wrong
/// in the permissive direction is worse than a blunt one that is always right about the safe case.
fn under_protected_root(exe: &std::path::Path) -> bool {
    ["ProgramFiles", "ProgramFiles(x86)", "SystemRoot"]
        .iter()
        .filter_map(std::env::var_os)
        .any(|root| exe.starts_with(PathBuf::from(root)))
}

/// Everything an install does *after* the SCM accepts the registration.
///
/// Separated so the caller can undo the registration as a whole if any of it fails — see the call
/// site. The credential is written here, last, rather than before the service exists: written
/// first, an install that then failed because the service was already registered had already
/// replaced the *running* service's token, which would keep serving on the one in its memory and
/// switch to a different one at its next restart, having reported a failure. Nothing is started
/// here, so there is no window in which the file exists and something is serving with it.
fn finish_install(
    service: &windows_service::service::Service,
    credentials: &[(String, String)],
) -> Result<()> {
    service
        .set_description(DESCRIPTION)
        .context("the service's description could not be set")?;
    // **Ten seconds by default on anything modern**, which is nowhere near a teardown that may be
    // releasing a live kernel — and unlike an ordinary stop, a system shutdown that runs out of
    // patience does not wait for us to finish. Raised to the same bound the stop itself reports,
    // and refreshed at every start in case the call timeout has moved since.
    service
        .set_preshutdown_timeout(stop_bound())
        .context("the service's preshutdown timeout could not be set")?;

    let token_at = token_file();
    secured_state_dir()?;
    // Never reuse an object we did not create: a pre-existing file at this path is an unprivileged
    // user's to own, and writing into it would leave them owning the credential. Removed and
    // created fresh, with `create_new`, so losing a race is a refusal rather than a silent reuse.
    let _ = std::fs::remove_file(&token_at);
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&token_at)
            .with_context(|| {
                format!(
                    "cannot create {} — something else created it first, which for a credential is \
                     a refusal rather than something to write through",
                    token_at.display()
                )
            })?;
        file.write_all(token_file_contents(credentials).as_bytes())
            .with_context(|| format!("cannot write {}", token_at.display()))?;
    }
    restrict_to_administrators(&token_at, "R")
}

/// Registers the service to run this exe with `--service --listen <addr>`.
pub fn install(addr: SocketAddr, allow_unprotected: bool) -> Result<()> {
    // Refused rather than warned about, and this changed once the token moved into a file: an
    // install has to *have* a credential to write it down, and a service registered without one is
    // a service that fails at every start. Validated here too, by the listener's own rules, so a
    // shell that could not start a foreground listener cannot register a service either.
    let credentials = crate::client::env_credentials(std::env::vars())?;
    if credentials.is_empty() {
        bail!(
            "set {} in this shell first — the install copies it into a file only SYSTEM and \
             Administrators can read, which is how the service gets it. A *machine-scope* \
             environment variable would work and must not be used: it is readable by every local \
             process, and this endpoint's `launch` runs arbitrary commands as \
             LocalSystem.\n    $env:{} = \"<a long random string>\"\n\nEvery {}_<NAME> in this \
             shell is copied too, each naming a client of its own — which under a service is the \
             only way to have more than one, since the file it reads is the whole of what it \
             accepts.",
            crate::listen::TOKEN_ENV,
            crate::listen::TOKEN_ENV,
            crate::listen::TOKEN_ENV
        );
    }

    let exe = std::env::current_exe().context("cannot find this executable's own path")?;
    if !under_protected_root(&exe) && !allow_unprotected {
        bail!(
            "{} is not under a directory Windows protects (%ProgramFiles%, %ProgramFiles(x86)% or \
             %SystemRoot%). The SCM would store that exact path for a LocalSystem auto-start \
             service, so whoever can write there — or write an engine DLL beside it — gets their \
             code run as SYSTEM at the next start.\n\nCopy the deployment somewhere protected and \
             install from there. For a development install, where the checkout is yours and the \
             machine is yours, pass {ALLOW_UNPROTECTED_FLAG}.",
            exe.display()
        );
    }
    let manager = ServiceManager::local_computer(
        None::<&OsStr>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context(
        "cannot open the service manager — installing a service needs an elevated shell (\"Run \
         as administrator\")",
    )?;

    let service = manager
        .create_service(
            &ServiceInfo {
                name: OsString::from(NAME),
                display_name: OsString::from(DISPLAY_NAME),
                service_type: SERVICE_TYPE,
                // Boot start, which is one of the three reasons to be a service at all: the
                // machine that exists to be debugged should be debuggable before anyone logs in.
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: exe,
                launch_arguments: launch_arguments(addr),
                dependencies: vec![],
                // `LocalSystem`. A kernel debugger needs privileges an ordinary service account
                // does not have, and this endpoint is already gated by its bearer token rather
                // than by the account it runs as.
                account_name: None,
                account_password: None,
            },
            // `DELETE` as well as `CHANGE_CONFIG`, because the rollback below needs it: a handle
            // without it fails the delete *silently*, and the "nothing was installed" this then
            // reports is a lie that leaves a half-registered service behind. Found by running it.
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE,
        )
        .context("cannot create the service (is it already installed?)")?;
    // From here, **anything that fails must take the service with it**. Moving the credential
    // after the SCM work fixed one half-done install (a failed create no longer replaces a running
    // service's token) and would otherwise create another: a registration left behind by a token
    // step that refused. An install either happened or it did not.
    if let Err(e) = finish_install(&service, &credentials) {
        let undone = service.delete().is_ok();
        // Waited out, not merely asked for. A delete marks a service and completes when the last
        // handle to it closes, so returning here without waiting makes "nothing was installed"
        // false for a moment — long enough that an operator fixing the problem and running the
        // command again is told the service already exists.
        drop(service);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline
            && manager
                .open_service(NAME, ServiceAccess::QUERY_STATUS)
                .is_ok()
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        // Reported honestly either way: a rollback that failed leaves a registration this command
        // claimed to have removed, which is the one outcome worse than the original error.
        return Err(if undone {
            e.context("nothing was installed — the partial registration was removed")
        } else {
            e.context(format!(
                "and `{NAME}` was left registered because it could not be removed again — run \
                 `{UNINSTALL_FLAG}` before trying once more"
            ))
        });
    }
    // **Ten seconds by default on anything modern**, which is nowhere near a teardown that may be
    // releasing a live kernel — and unlike an ordinary stop, a system shutdown that runs out of
    // patience does not wait for us to finish. Raised to the same bound the stop itself reports.

    println!(
        "installed `{NAME}`, which will run:\n    {} {} {} {}\nStart it with `net start {NAME}`, \
         or reboot — it is configured to start automatically.\nIt logs to {} (or wherever {} \
         points when the service starts).\n\nIt runs as LocalSystem, which has a profile directory \
         of its own: kernel connection profiles in your `%USERPROFILE%\\.windbg-mcp\\profiles.json` \
         are **not** visible to it. Configure those machine-wide instead — \
         `WINDBG_MCP_PROFILE_<NAME>` in the machine environment, or `WINDBG_MCP_PROFILES` pointing \
         at a file the service account can read.",
        std::env::current_exe().unwrap_or_default().display(),
        SERVICE_FLAG,
        crate::listen::LISTEN_FLAG,
        addr,
        log_path().display(),
        LOG_ENV,
    );
    Ok(())
}

/// Stops the service if it is running, and removes it.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .context(
            "cannot open the service manager — removing a service needs an elevated shell (\"Run \
             as administrator\")",
        )?;
    let service = manager
        .open_service(
            NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("no service named `{NAME}` is installed"))?;

    // Stopped *before* deletion is asked for, and waited on: a delete leaves a running service
    // marked for deletion until it exits, and this one has debug targets to let go of. Killing it
    // by reboot instead would leave a live kernel frozen.
    if service.query_status()?.current_state != ServiceState::Stopped {
        println!("stopping `{NAME}` — it releases its debug targets first…");
        service.stop().context("the service refused to stop")?;
        let deadline = std::time::Instant::now() + stop_bound();
        while std::time::Instant::now() < deadline {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        // Checked rather than assumed. `delete` on a service that is still running *succeeds* — it
        // marks it for deletion until the process exits — so falling through here would report a
        // clean removal, take the token with it, and leave a `LocalSystem` listener holding live
        // debug targets. Refusing leaves everything as it was, which is recoverable.
        let state = service.query_status()?.current_state;
        if state != ServiceState::Stopped {
            bail!(
                "`{NAME}` is still {state:?} after {:?}. Not deleting it, and not removing its \
                 token: a delete would only mark a running service, and this one may still be \
                 holding a debug target. Find out what it is waiting on (its log is at {}) and try \
                 again.",
                stop_bound(),
                log_path().display()
            );
        }
    }
    service
        .delete()
        .context("the service could not be deleted")?;
    // The token goes with it. Leaving a credential behind for a service that no longer exists is
    // the kind of tidy-up nobody remembers to do by hand.
    let token_at = token_file();
    match std::fs::remove_file(&token_at) {
        Ok(()) => println!(
            "removed `{NAME}` and its token file ({}).",
            token_at.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("removed `{NAME}`."),
        Err(e) => println!(
            "removed `{NAME}`, but its token file ({}) could not be deleted: {e}",
            token_at.display()
        ),
    }
    Ok(())
}

/// Tells the SCM the current [`stop_bound`], in case the call timeout has moved since install.
fn sync_preshutdown_timeout() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .context("cannot open the service manager")?;
    manager
        .open_service(NAME, ServiceAccess::CHANGE_CONFIG)
        .context("cannot open this service to update its configuration")?
        .set_preshutdown_timeout(stop_bound())
        .context("cannot set the preshutdown timeout")
}

define_windows_service!(ffi_service_main, service_main);

/// Hands this thread to the SCM. Returns when the service has stopped.
pub fn run() -> Result<()> {
    service_dispatcher::start(NAME, ffi_service_main).context(
        "this process was started with `--service` but is not running under the service control \
         manager. That flag is for the SCM to pass, not to type: install with \
         `--install-service --listen <addr>` and start the service.",
    )?;
    Ok(())
}

/// The SCM's entry point. Nothing here may panic across the FFI boundary, and there is no console
/// to print to, so every outcome ends up in the log file and in the service's exit code.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = serve_as_service() {
        tracing::error!("the service stopped with an error: {e:#}");
    }
}

fn serve_as_service() -> Result<()> {
    // A service starts in `%SystemRoot%\System32`. Moving to the exe's own directory makes the
    // engine bundle beside it resolve the way it does for a foreground listener — which is one of
    // the things being a service is supposed to make *more* predictable, not less.
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let _ = std::env::set_current_dir(dir);
    }

    // The token `install` wrote and locked down. Pointed at here rather than baked into the
    // command line the SCM stores, because that line is readable by every process on the machine —
    // which is the exact property the file exists to restore.
    //
    // SAFETY: this runs on the SCM's dispatcher thread before the async runtime exists and before
    // any thread of ours has been started, so there is no concurrent reader of the environment.
    if std::env::var_os(crate::listen::TOKEN_FILE_ENV).is_none() {
        let file = token_file();
        if file.exists() {
            unsafe { std::env::set_var(crate::listen::TOKEN_FILE_ENV, &file) };
        }
    }

    // **Re-applied at every start, not just at install.** The bound is derived from
    // `WINDBG_MCP_CALL_TIMEOUT_SECS`, which an operator can raise long after installing — and the
    // value the SCM holds would still be the one computed that day. Windows honours *its* copy
    // during a shutdown, so a drifted-short timeout means the OS stops waiting while a batch is
    // still unwinding, which is the frozen-kernel outcome all of this exists to avoid. Best-effort:
    // a service that cannot reopen itself should still serve, so this warns rather than refuses.
    if let Err(e) = sync_preshutdown_timeout() {
        tracing::warn!(
            "could not refresh the preshutdown timeout ({e:#}); the SCM keeps the value stored at install"
        );
    }

    let addr = match crate::listen::requested(&std::env::args().collect::<Vec<_>>()) {
        Some(addr) => addr?,
        None => bail!(
            "the service was installed without `{} <addr>`, so there is nothing to bind. Reinstall \
             it: `--uninstall-service` then `--install-service --listen <addr>`.",
            crate::listen::LISTEN_FLAG
        ),
    };

    // The stop signal, and the acknowledgement that it has been acted on. A `oneshot` rather than a
    // flag because the SCM's handler runs on its own thread and must return promptly — it may only
    // *ask*, and the runtime below does the releasing.
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut stop_tx = Some(stop_tx);
    let status_handle = service_control_handler::register(NAME, move |control| match control {
        // Answering this is not optional: a service that does not is reported as not responding.
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Preshutdown => {
            if let Some(tx) = stop_tx.take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .context("cannot register the service control handler")?;

    let running = |state: ServiceState, wait_hint: Duration| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        // `PRESHUTDOWN` as well as `STOP`, and the distinction is the point: an ordinary
        // `SHUTDOWN` gives a service a few seconds, while a preshutdown notification is sent
        // earlier and honours the wait hint — which is what a kernel target being released needs.
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    };
    // `StopPending` carries a rising checkpoint, which is how the SCM tells "still working" from
    // "hung" — the state that accepts no controls, because by then there is nothing left to ask.
    let pending = |checkpoint: u32, wait_hint: Duration| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint,
        wait_hint,
        process_id: None,
    };
    // `StartPending`, not `Running`: the socket is not bound yet, and on a non-loopback address at
    // boot the bind may wait for the adapter to appear. Reporting `Running` here would have
    // `Start-Service` succeed while there is no endpoint, and anything sequenced after it fail.
    // The hint covers that wait; `Running` is reported from the `ready` callback below, once there
    // really is something listening.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        // **Stoppable while starting**, which is not the obvious choice and is the one that
        // matters: with no controls accepted here, a service waiting out the bind retry cannot be
        // stopped at all — `sc stop` is refused with `1052` and it sits in `StartPending` for the
        // full patience. Accepting `STOP` is what lets the shutdown future the bind is raced
        // against ever resolve. Found by starting one against an address that does not exist.
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: crate::listen::BIND_PATIENCE + CHECKPOINT_EVERY,
        process_id: None,
    })?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?
        .block_on(async move {
            // Set before the last status is reported, so the ticker below cannot put a
            // `StopPending` on the wire after the `Stopped` that ends the service.
            let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let served = crate::serve_http(
                addr,
                {
                    let finished = finished.clone();
                    async move {
                        let _ = stop_rx.await;
                        tracing::info!("service stop requested; releasing every debug target");
                        // Told before the releasing starts, not after: the SCM's clock is already
                        // running, and a wait hint that arrives once the work is done has bounded
                        // nothing.
                        let bound = stop_bound();
                        let _ = status_handle.set_service_status(pending(1, bound));
                        // And kept being told. The releasing happens *after* the accept loop returns —
                        // in `serve_http`, out of reach of this future — so without something ticking
                        // here the SCM sees one status and then silence for as long as a batch takes to
                        // unwind. Dies with the runtime, which is dropped moments after the stop.
                        tokio::spawn(async move {
                            let mut checkpoint = 1u32;
                            loop {
                                tokio::time::sleep(CHECKPOINT_EVERY).await;
                                if finished.load(std::sync::atomic::Ordering::SeqCst) {
                                    return;
                                }
                                checkpoint += 1;
                                let _ =
                                    status_handle.set_service_status(pending(checkpoint, bound));
                            }
                        });
                    }
                },
                || {
                    let _ = status_handle
                        .set_service_status(running(ServiceState::Running, Duration::default()));
                },
            )
            .await;
            finished.store(true, std::sync::atomic::Ordering::SeqCst);
            // Reported from here, where both the handle and the outcome are in scope, so a service
            // that failed says so in its exit code rather than only in the log.
            let exit_code = match &served {
                Ok(()) => ServiceExitCode::Win32(0),
                Err(_) => ServiceExitCode::ServiceSpecific(1),
            };
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code,
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            served
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_is_read_off_the_command_line_and_only_when_asked_for() {
        let argv = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert_eq!(requested(&argv(&["windbg-mcp"])), None);
        assert_eq!(
            requested(&argv(&["windbg-mcp", "--listen", "127.0.0.1:8765"])),
            None
        );
        assert_eq!(
            requested(&argv(&["windbg-mcp", SERVICE_FLAG])),
            Some(Role::Run)
        );
        assert_eq!(
            requested(&argv(&[
                "windbg-mcp",
                INSTALL_FLAG,
                "--listen",
                "127.0.0.1:8765"
            ])),
            Some(Role::Install)
        );
        assert_eq!(
            requested(&argv(&["windbg-mcp", UNINSTALL_FLAG])),
            Some(Role::Uninstall)
        );
    }

    /// The SCM stores this once, at install time, and nothing re-derives it — so a service that
    /// registers cleanly and then fails at every start is the shape this guards against.
    #[test]
    fn the_installed_command_line_starts_the_service_on_the_address_it_was_given() {
        let args = launch_arguments("127.0.0.1:8765".parse().expect("a literal address"));
        let rendered: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(rendered, vec![SERVICE_FLAG, "--listen", "127.0.0.1:8765"]);
        // And the flag the SCM passes is the one `requested` answers `Run` to, which is the join
        // between installing and starting that nothing else checks.
        assert_eq!(requested(&rendered), Some(Role::Run));
    }

    /// The file the installer writes is the file the listener reads — asserted end to end, because
    /// the two halves are in different modules and nothing else joins them. A service that starts
    /// and accepts nobody is the failure shape, and it costs a reinstall to find out.
    #[test]
    fn what_the_install_writes_is_what_the_listener_reads_back() {
        // Never opened — `TokenFile` parses text — but it is the real path, so the refusals
        // this exercises name what an operator would actually go and look at.
        let at = token_file();
        let read_back = |written: &str| {
            crate::client::Credentials::from_entries(
                std::iter::empty(),
                Some(
                    crate::client::TokenFile::parse(written, &at)
                        .unwrap_or_else(|e| panic!("the installer wrote {written:?}: {e}")),
                ),
            )
            .unwrap_or_else(|e| panic!("the installer wrote {written:?}: {e}"))
        };

        // One client called `local` keeps the shape every existing install has: the token, and
        // nothing around it.
        let one = [(
            crate::client::Client::LOCAL.to_string(),
            "s3cret".to_string(),
        )];
        let written = token_file_contents(&one);
        assert_eq!(written, "s3cret", "a single local token is written bare");
        assert_eq!(
            read_back(&written).client_for("s3cret").map(|c| c.name()),
            Some("local")
        );

        // Anything else is the JSON object, which is the only shape that can carry more than one —
        // and under a service the only way to have a second client at all.
        for credentials in [
            vec![
                ("local".to_string(), "for-local".to_string()),
                ("ci".to_string(), "for-ci".to_string()),
            ],
            // A shell with only a named token configures no `local`, and that is not a special
            // case: it is one client, which happens not to be that one.
            vec![("ci".to_string(), "for-ci".to_string())],
            // And a lone `local` whose token begins with `{`, which the bare shape cannot carry:
            // the reader would take it for the JSON one. Nothing is wrong with the token, so it
            // goes in the object rather than being refused.
            vec![("local".to_string(), "{not-json-just-a-token".to_string())],
            // The nastier one: a token that *is* a one-entry object naming `local`. Written bare
            // it parses — to a different token — so this asserts the whole credential survives,
            // not just the client's name.
            vec![(
                "local".to_string(),
                r#"{"local":"replacement"}"#.to_string(),
            )],
        ] {
            let written = token_file_contents(&credentials);
            let creds = read_back(&written);
            assert_eq!(creds.len(), credentials.len());
            for (name, token) in &credentials {
                assert_eq!(
                    creds.client_for(token).map(|c| c.name()),
                    Some(name.as_str()),
                    "{written}"
                );
            }
        }
    }

    /// The log has to land somewhere a service account can write and an operator will look, and it
    /// has to be overridable — a smoke run cannot be writing to `%ProgramData%`.
    ///
    /// **And moving it must not move the token**, which is the bug this test was written for. The
    /// token path was derived from the log path, so redirecting the log made `install` write the
    /// credential in one place and the service look in another: it started, found nothing, and
    /// exited with a service-specific error and an empty log. Found by running the thing.
    #[test]
    fn the_log_is_overridable_and_the_token_does_not_follow_it() {
        // SAFETY: single-threaded test, and the variable is read only through `log_path`.
        unsafe { std::env::set_var(LOG_ENV, r"C:\somewhere\else.log") };
        assert_eq!(log_path(), PathBuf::from(r"C:\somewhere\else.log"));
        assert!(
            token_file().ends_with(r"windbg-mcp\token"),
            "redirecting the log moved the token to {:?}",
            token_file()
        );
        unsafe { std::env::remove_var(LOG_ENV) };
        let default = log_path();
        assert!(default.ends_with(r"windbg-mcp\service.log"), "{default:?}");
        assert_eq!(default.parent(), token_file().parent());
    }
}
