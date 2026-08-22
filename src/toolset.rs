//! Which of this server's fifty-one tools a run advertises.
//!
//! The tool surface is paid **once per conversation, before anything is debugged**, and it is
//! 67,658 bytes — roughly 17k tokens. Three quarters of that is prose, and the prose is what tells
//! a model how to drive the tools, so there is no strip here the way there was in
//! [`crate::schema`]: `FOLLOWUPS.md` item 24 measured it and the only honest lever left is the one
//! this module is — **not offering every tool to every caller**.
//!
//! Nothing changes for a client that says nothing. `--tools` is the whole interface, the default is
//! every tool, and a narrowed surface costs no description a word.
//!
//! # What a group is
//!
//! A group is *an activity*, not a subsystem: the tools you reach for while doing one kind of
//! debugging. A caller reading a crash dump has no use for the nine TTD tools or the ten allocator
//! ones, and pays 22,747 bytes for them at the start of every conversation.
//!
//! ```text
//!   group      tools   bytes   what it is for
//!   session       10   12,161  opening a target, ending it, and watching this server
//!   allocator     10   15,914  pool and heap walks, and `walk_memory`
//!   inspect        9   10,192  registers, stacks, memory, modules, symbols, raw commands
//!   ttd            9    6,833  recording, indexing and querying a Time Travel trace
//!   ioctl          6    6,494  driver objects, IRP stacks, and dispatch reachability
//!   exec           5    3,406  breakpoints and execution control
//!   batch          1    9,746  `debug_batch`
//!   crash          1    2,912  `crash_triage`
//! ```
//!
//! # `session` is always in the surface
//!
//! Not a convenience: every other tool here routes by a `session_id`, and this server is the only
//! thing that can issue one. A surface with `registers` and no opener cannot be used at all, so a
//! spec that leaves one out is asking for something that does not exist. It is 12,161 bytes, and it
//! is the floor of any usable surface — `--tools crash` is eleven tools, not one, and the startup
//! line says so rather than leaving the addition to be discovered.
//!
//! # Where this stops
//!
//! **Server-wide**, decided from `argv` before anything is built. The listener names its clients
//! already ([`crate::client`]), so a per-caller surface — a local model getting twenty tools and a
//! full client fifty-one on the same server — is the obvious next step and is `FOLLOWUPS.md` item
//! 36. It is deliberately not this change: the router is `WindbgServer::tool_router()`, a
//! static, and making it per-instance is a separate argument with its own two-client coverage to
//! write.

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
        tools: &["crash_triage"],
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
        let mut included = BTreeSet::new();
        let mut named_anything = false;
        let mut everything = false;

        for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            named_anything = true;
            if entry == ALL {
                // Noted and carried on with, not returned on. Returning here would stop validating
                // the rest, so `all,ttdd` served all 51 tools while `ttdd,all` was refused — the
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
                        "`{FLAG} {spec}`: `{entry}` is neither a group nor a tool. {}",
                        Self::vocabulary()
                    ));
                }
            }
        }

        if !named_anything {
            return Err(format!(
                "`{FLAG} {spec}` selects nothing. {}",
                Self::vocabulary()
            ));
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
        assert_eq!(set.summary(), "11 of 51 tools (session, crash)");
    }

    #[test]
    fn a_bare_tool_name_selects_that_tool() {
        let set = Toolset::parse("registers,backtrace").expect("both are tools");
        assert!(set.includes("registers"));
        assert!(set.includes("backtrace"));
        assert!(!set.includes("disassemble"));
        assert_eq!(
            set.summary(),
            "12 of 51 tools (session, backtrace, registers)"
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
