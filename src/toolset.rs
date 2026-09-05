//! Which of this server's fifty-six tools a run advertises.
//!
//! The tool surface is paid **once per conversation, before anything is debugged**, and it is
//! 79,825 bytes — roughly 20k tokens (measured 2026-09-05; every figure here moves with any edit
//! to a description, so re-derive rather than cite). Seven tenths of that is prose, and the prose is what tells
//! a model how to drive the tools, so there is no strip here the way there was in
//! [`crate::schema`]: `FOLLOWUPS.md` item 24 measured it and the only honest lever left is the one
//! this module is — **not offering every tool to every caller**.
//!
//! Nothing changes for a client that says nothing. `--tools` is the whole interface and the default
//! is every tool. A narrowed surface costs a description one thing only: the sentences pointing at
//! tools it no longer has (`FOLLOWUPS.md` item 41, `TOOL_NOTES` in [`crate::server`]), which is why
//! the bytes below do not add up to what a spec actually serves — see the note under the table.
//!
//! # What a group is
//!
//! A group is *an activity*, not a subsystem: the tools you reach for while doing one kind of
//! debugging. A caller reading a crash dump has no use for the nine TTD tools or the ten allocator
//! ones, and pays 23,286 bytes for them at the start of every conversation.
//!
//! ```text
//!   group      tools   bytes   what it is for
//!   allocator     10   16,457  pool and heap walks, and `walk_memory`
//!   session       10   12,817  opening a target, ending it, and watching this server
//!   inspect        9   11,626  registers, stacks, memory, modules, symbols, raw commands
//!   batch          1   10,021  `debug_batch`
//!   exec           8    9,206  breakpoints and execution control
//!   ttd            9    6,829  recording, indexing and querying a Time Travel trace
//!   ioctl          6    6,494  driver objects, IRP stacks, and dispatch reachability
//!   crash          3    6,375  a bug check, a user-mode fault, and an error code
//! ```
//!
//! **Those are shares of the whole surface, and they do not sum to a narrowed one.** `crash` reads
//! 18,026 bytes, not the 19,192 its two rows add to, because the thirteen tools it keeps also stop
//! carrying the sentences that pointed at `modules`, `debug_batch`, `backtrace`, `continue_async`
//! and `break_in` — 1,166 bytes of them. A spec is always cheaper than its rows suggest, never
//! dearer.
//!
//! # `session` is always in the surface
//!
//! Not a convenience: every other tool here routes by a `session_id`, and this server is the only
//! thing that can issue one. A surface with `registers` and no opener cannot be used at all, so a
//! spec that leaves one out is asking for something that does not exist. On its own it is 11,714
//! bytes, and that is the floor of any usable surface — `--tools crash` is thirteen tools, not three,
//! and the startup line says so rather than leaving the addition to be discovered.
//!
//! # Who a surface belongs to
//!
//! **A run has one, and a client may have its own.** `--tools` is the run's, decided from `argv`
//! before anything is built, and it is the whole story under stdio — one process, one client, and
//! the flag is right there on the command line that started it.
//!
//! A listener names its clients already ([`crate::client`]), and they do not have one budget
//! between them: the arrangement this exists for is a local model that can hold twenty tools and a
//! hosted client that can hold fifty-six, pointed at the same Windows box and the same debug
//! sessions and told apart by their bearer tokens. So a client may be configured with a spec of
//! its own — `WINDBG_MCP_TOOLS_<NAME>`, or a `tools` field in the credential file — and is served
//! that instead of the run's. The run's `--tools` is the **default**, not a ceiling: a client's
//! own spec replaces it rather than intersecting with it, because an intersection can produce a
//! surface neither the operator nor the client ever named.
//!
//! **When a change takes effect is a decision, and the answer is "the next time the client is
//! identified".** A surface is fixed on the line that captures the caller's identity — the
//! listener's service factory, which rmcp runs once per MCP session and once per request on
//! `2026-07-28`, so a client on that revision picks a change up with nothing done to it. Nothing
//! sends `notifications/tools/list_changed` after a reload: this server keeps no peer handle to
//! notify through, and the stateless revision has no session to notify at all, so it would be a
//! guarantee on one revision and silence on the other. A client holding a session sees the new
//! surface when it reconnects, and keeps the one it listed until then. See [`Chosen`] for the
//! other half of
//! that — what a caller is told when it calls a tool the surface does not have.

use std::collections::BTreeSet;

/// The flag, on this server's own command line.
pub const FLAG: &str = "--tools";

/// The spec that means what a run with no `--tools` at all serves.
pub const ALL: &str = "all";

/// The group every surface has, whatever was asked for. See the module docs.
const ALWAYS: &str = "session";

struct Group {
    name: &'static str,
    tools: &'static [&'static str],
}

/// Every tool this server has, in exactly one group.
///
/// `every_tool_belongs_to_exactly_one_group` checks that against the live `tools/list` in both
/// directions, because both ways of being wrong are silent: a tool missing from here vanishes from
/// every narrowed surface, and a name here that no longer exists makes `--tools` accept a spec that
/// selects nothing.
const GROUPS: &[Group] = &[
    Group {
        name: ALWAYS,
        tools: &[
            "open_dump",
            "open_trace",
            "attach_kernel",
            "attach_kernel_local",
            "attach_process",
            "launch",
            "end_session",
            "session_status",
            "server_log",
            "interrupt",
        ],
    },
    Group {
        name: "inspect",
        tools: &[
            "registers",
            "backtrace",
            "disassemble",
            "read_memory",
            "modules",
            "threads",
            "execute",
            "dx",
            "set_symbol_path",
        ],
    },
    Group {
        name: "exec",
        tools: &[
            "go",
            "step_over",
            "step_into",
            "run_to_address",
            "set_breakpoint",
            "continue_async",
            "wait_for_stop",
            "break_in",
        ],
    },
    Group {
        name: "ttd",
        tools: &[
            "record_trace",
            "index_trace",
            "goto_position",
            "reverse_go",
            "step_back",
            "step_over_back",
            "ttd_calls",
            "ttd_memory",
            "ttd_events",
        ],
    },
    Group {
        name: "ioctl",
        tools: &[
            "decode_ioctl",
            "driver_object",
            "device_object",
            "irp_stack",
            "ioctl_trace",
            "reachable_from_dispatch",
        ],
    },
    Group {
        name: "allocator",
        tools: &[
            "pool_find_tag",
            "pool_chunk",
            "pool_census",
            "pool_diagnostics",
            "heap_list",
            "heap_allocations",
            "heap_chunk",
            "heap_census",
            "heap_diagnostics",
            "walk_memory",
        ],
    },
    Group {
        name: "crash",
        tools: &["crash_triage", "exception_triage", "decode_error_reporting"],
    },
    Group {
        name: "batch",
        tools: &["debug_batch"],
    },
];

/// The tools a run advertises.
///
/// `None` is every tool, and is not the same as a set that happens to hold all of them: it is the
/// answer for a run that was never asked to narrow anything, so a tool added to `src/server.rs` and
/// forgotten here is still served by default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toolset {
    included: Option<BTreeSet<&'static str>>,
}

impl Toolset {
    /// Every tool, which is what a run with no `--tools` serves.
    pub fn all() -> Self {
        Self { included: None }
    }

    /// The surface this command line asked for, or `None` if it did not ask.
    ///
    /// Shaped like [`crate::listen::requested`] — `Some(Err(_))` is "you asked, and the spec is
    /// wrong", which has to be a usage error at startup rather than a surface that quietly serves
    /// something else.
    pub fn requested(args: &[String]) -> Option<Result<Self, String>> {
        let at = args.iter().position(|arg| arg == FLAG)?;
        Some(match args.get(at + 1) {
            Some(spec) => Self::parse(spec),
            None => Err(format!(
                "`{FLAG}` needs a spec, e.g. `{FLAG} session,inspect,crash`. {}",
                Self::vocabulary()
            )),
        })
    }

    /// The spec as it was written, for the one caller that has to store the text rather than the
    /// parsed set: `--install-service` writes a command line the SCM keeps and this program parses
    /// again at every start. Returns `None` for a command line with no `{FLAG}` on it.
    pub fn spec_in(args: &[String]) -> Option<&str> {
        let at = args.iter().position(|arg| arg == FLAG)?;
        args.get(at + 1).map(String::as_str)
    }

    /// A comma-separated spec: `all`, or any mix of group names and tool names.
    ///
    /// Tool names are allowed beside group names because a group is the smallest *useful* surface
    /// and not the smallest possible one — on a box where the window is bought in RAM, "the four
    /// tools I actually call" is a real answer. They are resolved against [`GROUPS`], so a spec can
    /// only ever name a tool this server has.
    pub fn parse(spec: &str) -> Result<Self, String> {
        Self::parse_from(spec, &format!("`{FLAG} {spec}`"))
    }

    /// The same, told what to call the thing it is reading.
    ///
    /// The vocabulary is written down in three places now — this flag, a `WINDBG_MCP_TOOLS_<NAME>`
    /// variable, and a client's entry in the credential file — and a refusal that named the wrong
    /// one would send an operator to edit a command line they never typed. So the source arrives
    /// already rendered, for the same reason a credential's source is in [`crate::client`]: how a
    /// source is referred to is the source's business, and one template cannot render a flag, a
    /// variable and a file entry.
    pub fn parse_from(spec: &str, source: &str) -> Result<Self, String> {
        let mut included = BTreeSet::new();
        let mut named_anything = false;
        let mut everything = false;

        for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            named_anything = true;
            if entry == ALL {
                // Noted and carried on with, not returned on. Returning here would stop validating
                // the rest, so `all,ttdd` served all 56 tools while `ttdd,all` was refused — the
                // same spec, judged by where the typo happened to sit. A refusal that depends on
                // entry order is worse than no refusal, because it is the one nobody reproduces.
                everything = true;
                continue;
            }
            if let Some(group) = GROUPS.iter().find(|g| g.name == entry) {
                included.extend(group.tools.iter().copied());
                continue;
            }
            match GROUPS
                .iter()
                .flat_map(|g| g.tools.iter())
                .find(|tool| **tool == entry)
            {
                Some(tool) => {
                    included.insert(*tool);
                }
                None => {
                    return Err(format!(
                        "{source}: `{entry}` is neither a group nor a tool. {}",
                        Self::vocabulary()
                    ));
                }
            }
        }

        if !named_anything {
            return Err(format!("{source} selects nothing. {}", Self::vocabulary()));
        }

        // After the loop, so every name in the spec has been checked first. `all` beside a group is
        // not an error — it is a wider request that happens to name a subset of itself — but a name
        // this server does not have is one whatever else the spec says.
        if everything {
            return Ok(Self::all());
        }

        // Every other tool routes by a `session_id` that only these can issue — see the module
        // docs. Added rather than demanded, and reported at startup so it is never a surprise.
        included.extend(
            GROUPS
                .iter()
                .find(|g| g.name == ALWAYS)
                .expect("the always-on group is one of the groups")
                .tools
                .iter()
                .copied(),
        );

        Ok(Self {
            included: Some(included),
        })
    }

    /// Every tool this server has, for the assertions that have to range over all of them.
    ///
    /// `GROUPS` is the table and stays private - this is the read-only view of it that
    /// `src/server.rs` needs to check that no client's `instructions` name a tool it is not
    /// served.
    ///
    /// **`cfg(test)` because every caller is an assertion**, all of them in `src/server.rs`'s
    /// test module: the prose checks that no description, fragment or note names a tool its own
    /// surface does not serve. Nothing in a shipping build ranges over the whole table - a
    /// surface answers `includes` for the tools it was asked about - so without the gate this is
    /// dead code in the `windbg-mcp` binary, which `cargo clippy -- -D warnings` fails on. CI
    /// runs clippy without `-D warnings`, so the gate is what keeps the stricter local command
    /// (the one `CLAUDE.md` prescribes) green.
    #[cfg(test)]
    pub fn every_tool() -> impl Iterator<Item = &'static str> {
        GROUPS.iter().flat_map(|group| group.tools.iter().copied())
    }

    /// Is this tool served?
    pub fn includes(&self, name: &str) -> bool {
        match &self.included {
            None => true,
            Some(included) => included.contains(name),
        }
    }

    /// Does this server have a tool by this name at all, whether or not it is served?
    ///
    /// The difference is the whole reason a refusal can be useful: "no such tool" and "not on this
    /// server's surface" are the same `tool not found` to rmcp, and only the second one has a
    /// remedy the caller's operator can act on.
    pub fn exists(name: &str) -> bool {
        GROUPS
            .iter()
            .flat_map(|g| g.tools.iter())
            .any(|tool| *tool == name)
    }

    /// Drop from a router every tool this surface does not serve.
    ///
    /// Reaches `map` directly rather than through `remove_route`, which would need the names
    /// collected first to avoid borrowing the router twice. The two are equivalent here: the only
    /// thing `remove_route` does beyond this is preserve rmcp's `disabled` set, and nothing in this
    /// crate ever disables a route.
    pub fn narrow<S>(&self, router: &mut rmcp::handler::server::tool::ToolRouter<S>) {
        let Some(included) = &self.included else {
            return;
        };
        router
            .map
            .retain(|name, _| included.contains(name.as_ref()));
    }

    /// What this surface is, for the startup log. Names the groups it covers whole, then whatever
    /// is left over, so `--tools crash` reads as the eleven tools it is.
    pub fn summary(&self) -> String {
        let Some(included) = &self.included else {
            return format!("all {} tools", Self::total());
        };

        let mut parts = Vec::new();
        let mut loose: Vec<&str> = Vec::new();
        for group in GROUPS {
            let held = group.tools.iter().filter(|t| included.contains(*t)).count();
            if held == group.tools.len() {
                parts.push(group.name.to_string());
            } else {
                loose.extend(
                    group
                        .tools
                        .iter()
                        .filter(|t| included.contains(*t))
                        .copied(),
                );
            }
        }
        // Sorted, so the line does not depend on the order [`GROUPS`] happens to list a group's
        // tools in — that order is the table's business and reshuffling it should not change what
        // a startup log says.
        loose.sort_unstable();
        parts.extend(loose.into_iter().map(str::to_string));
        format!(
            "{} of {} tools ({})",
            included.len(),
            Self::total(),
            parts.join(", ")
        )
    }

    /// The group names and the `all` spelling, for a refusal that has to be actionable.
    fn vocabulary() -> String {
        let names: Vec<&str> = GROUPS.iter().map(|g| g.name).collect();
        format!(
            "Groups: {} (or `{ALL}`, or any tool's own name); `{ALWAYS}` is always included.",
            names.join(", ")
        )
    }

    fn total() -> usize {
        GROUPS.iter().map(|g| g.tools.len()).sum()
    }

    /// What a caller gets when it calls a tool this build has and this surface does not.
    ///
    /// rmcp would answer the router's own `tool not found`, which is the right status and the
    /// wrong sentence: it is what a typo gets, and this is not a typo — the tool exists and an
    /// operator narrowed the surface. The only part of that a caller can act on is **which of two
    /// configurations to ask about**, since it can see neither this server's command line nor its
    /// client list; that is [`Chosen`], and it is why this message is built here rather than
    /// where the refusal is returned.
    pub fn refusal(&self, tool: &str, client: &str, chosen: Chosen) -> String {
        format!(
            "`{tool}` is a tool this server has, but it is not on the surface {} ({}). {}",
            match chosen {
                Chosen::ForTheRun => "this run advertises".to_string(),
                Chosen::ForThisClient => format!("it serves `{client}`"),
            },
            self.summary(),
            match chosen {
                Chosen::ForTheRun => format!(
                    "It was started with `{FLAG}`; widen that spec, or drop it to serve every \
                     tool."
                ),
                // **Both sources, because only one of them exists on any given host.** The
                // command edits the credential file a *service* reads and refuses outright where
                // no service is installed — so naming it alone is advice a foreground listener's
                // operator cannot take, and that is the deployment a narrowed client is most
                // likely to be on (review on #196).
                Chosen::ForThisClient => format!(
                    "That is `{client}`'s own surface rather than this run's, so widening it is a \
                     change to this listener's client list: `{} {client} {FLAG} <spec>` under a \
                     service, or `{}_{}` for a foreground one. Neither needs a restart.",
                    crate::service::SET_CLIENT_TOOLS_FLAG,
                    crate::client::TOOLS_ENV,
                    client.to_ascii_uppercase(),
                ),
            }
        )
    }
}

/// Whose choice a surface was.
///
/// The only part of a [refusal](Toolset::refusal) a caller can act on. It can see neither this
/// server's command line nor its client list, so a message that named the wrong one of the two
/// would send its operator to widen a spec that is not the one in force — and the two are changed
/// by different commands, on different machines' worth of privilege.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chosen {
    /// [`FLAG`] on this run's command line, or its absence. Every stdio run, and every client of a
    /// listener that was not given a surface of its own.
    ForTheRun,
    /// This client's own entry in the listener's configuration — a `WINDBG_MCP_TOOLS_<NAME>`
    /// variable, or a `tools` field in the credential file.
    ForThisClient,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tool_is_in_two_groups() {
        let mut seen = BTreeSet::new();
        for group in GROUPS {
            for tool in group.tools {
                assert!(seen.insert(*tool), "`{tool}` is in two groups");
            }
        }
        assert_eq!(seen.len(), Toolset::total());
    }

    /// A group name that is also a tool name would make a spec ambiguous, and the resolution order
    /// in [`Toolset::parse`] would decide it silently.
    #[test]
    fn no_group_is_named_after_a_tool() {
        for group in GROUPS {
            assert!(
                !Toolset::exists(group.name),
                "the group `{}` is also a tool name",
                group.name
            );
        }
    }

    #[test]
    fn no_flag_means_every_tool() {
        let all = Toolset::all();
        assert!(all.includes("debug_batch"));
        assert!(all.includes("ttd_calls"));
        // Even one this table has never heard of, which is the point of `None`.
        assert!(all.includes("a_tool_added_tomorrow"));
        assert_eq!(Toolset::requested(&["--listen".into()][..]), None);
    }

    #[test]
    fn a_group_brings_its_tools_and_the_session_tools() {
        let set = Toolset::parse("crash").expect("`crash` is a group");
        assert!(set.includes("crash_triage"));
        assert!(set.includes("open_dump"), "an opener is always served");
        assert!(set.includes("end_session"));
        assert!(!set.includes("ttd_calls"));
        assert!(!set.includes("debug_batch"));
        assert_eq!(set.summary(), "13 of 56 tools (session, crash)");
    }

    #[test]
    fn a_bare_tool_name_selects_that_tool() {
        let set = Toolset::parse("registers,backtrace").expect("both are tools");
        assert!(set.includes("registers"));
        assert!(set.includes("backtrace"));
        assert!(!set.includes("disassemble"));
        assert_eq!(
            set.summary(),
            "12 of 56 tools (session, backtrace, registers)"
        );
    }

    #[test]
    fn all_is_every_tool_however_it_is_spelled() {
        assert_eq!(Toolset::parse("all").expect("`all` parses"), Toolset::all());
        assert_eq!(
            Toolset::parse("crash,all").expect("`all` wins"),
            Toolset::all()
        );
    }

    /// `all` is not an escape from validation, and it is not one *whichever side of the typo it
    /// sits on*. Both spellings were not always refused: `all` used to return the moment it was
    /// read, so `all,ttdd` served every tool and `ttdd,all` failed — the same spec, decided by
    /// entry order (#195 review).
    #[test]
    fn a_typo_beside_all_is_still_a_typo() {
        for spec in ["all,ttdd", "ttdd,all"] {
            let error = Toolset::parse(spec).expect_err("`ttdd` is not a group");
            assert!(
                error.contains("`ttdd` is neither a group nor a tool"),
                "`{spec}`: {error}"
            );
        }
    }

    #[test]
    fn a_spec_that_names_nothing_is_refused() {
        let error = Toolset::parse("  ,, ").expect_err("an empty spec selects nothing");
        assert!(error.contains("selects nothing"), "{error}");
        assert!(
            error.contains("allocator"),
            "a refusal names the groups: {error}"
        );
    }

    #[test]
    fn an_unknown_name_is_refused_and_the_message_says_what_is_valid() {
        let error = Toolset::parse("inspect,ttdd").expect_err("`ttdd` is not a group");
        assert!(
            error.contains("`ttdd` is neither a group nor a tool"),
            "{error}"
        );
        assert!(error.contains("session, inspect, exec, ttd"), "{error}");
    }

    #[test]
    fn the_flag_without_a_spec_is_a_usage_error_rather_than_a_silent_default() {
        let args = vec![FLAG.to_string()];
        let error = Toolset::requested(&args)
            .expect("the flag was given")
            .expect_err("with nothing after it");
        assert!(error.contains("needs a spec"), "{error}");
    }

    /// A refusal names the thing the operator has to go and edit, which is not always the flag.
    ///
    /// The vocabulary is written down in three places now — this flag, a `WINDBG_MCP_TOOLS_<NAME>`
    /// variable, and a client's entry in the credential file — and a message that always said
    /// `--tools` would send an operator to a command line that has nothing to do with the spec
    /// they wrote.
    #[test]
    fn a_refusal_names_the_source_the_spec_was_written_in() {
        let error = Toolset::parse_from("crash,ttdd", "`WINDBG_MCP_TOOLS_CI`")
            .expect_err("`ttdd` is not a group");
        assert!(error.starts_with("`WINDBG_MCP_TOOLS_CI`: "), "{error}");
        assert!(
            error.contains("`ttdd` is neither a group nor a tool"),
            "{error}"
        );
        assert!(!error.contains(FLAG), "{error}");
        // And the flag's own spelling of the same refusal is unchanged, which is what `parse`
        // exists for.
        assert!(
            Toolset::parse("crash,ttdd")
                .expect_err("`ttdd` is not a group")
                .starts_with("`--tools crash,ttdd`: "),
        );
    }

    /// The surface a client is refused from is described by whoever chose it.
    ///
    /// A caller can see neither this server's command line nor its client list, so the only part
    /// of this message worth anything is which of the two its operator has to widen — and naming
    /// the wrong one sends them to a spec that is not in force.
    #[test]
    fn a_refusal_points_at_whichever_configuration_chose_the_surface() {
        let surface = Toolset::parse("crash").expect("`crash` is a group");

        let run = surface.refusal("debug_batch", "bench", Chosen::ForTheRun);
        assert!(run.contains("this run advertises"), "{run}");
        assert!(run.contains("It was started with `--tools`"), "{run}");
        assert!(!run.contains("bench"), "a run's surface is nobody's: {run}");

        let own = surface.refusal("debug_batch", "bench", Chosen::ForThisClient);
        assert!(own.contains("it serves `bench`"), "{own}");
        assert!(
            own.contains("--set-listen-client-tools bench --tools <spec>"),
            "the remedy has to be the command that changes *this* surface: {own}"
        );
        // **And the other place that surface can be configured.** That command edits the file a
        // *service* reads and refuses where none is installed, so naming it alone is advice a
        // foreground listener's operator cannot take (review on #196).
        assert!(
            own.contains("WINDBG_MCP_TOOLS_BENCH"),
            "a foreground listener's operator has no such command: {own}"
        );
        // Both name the tool and what is served, because those do not depend on who chose it.
        for said in [&run, &own] {
            assert!(said.contains("`debug_batch`"), "{said}");
            assert!(said.contains("13 of 56 tools (session, crash)"), "{said}");
        }
    }

    #[test]
    fn the_flag_reads_the_argument_after_it() {
        let args = vec![
            "--listen".into(),
            "127.0.0.1:0".into(),
            FLAG.to_string(),
            "inspect".into(),
        ];
        let set = Toolset::requested(&args)
            .expect("the flag was given")
            .expect("`inspect` is a group");
        assert!(set.includes("registers"));
        assert!(!set.includes("pool_chunk"));
    }
}
