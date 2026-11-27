//! The skills this server serves itself, over MCP (SEP-2640, `io.modelcontextprotocol/skills`).
//!
//! A skill is a directory with a `SKILL.md` at its root, the format `skills/` already holds for the
//! Claude Code plugin. The extension carries the same files over the protocol instead: `skills/list`
//! and `skills/get` describe each skill with a digest and a size for every file, and the files
//! themselves are ordinary resources read with `resources/read`, at `skill://<name>/<path>`. That
//! reaches every client the plugin does not — a listener's remote callers, a release zip or Scoop
//! install with no plugin beside it, a host that is not Claude Code.
//!
//! **Compiled in, not read from disk.** A release zip carries the exe, `LICENSE` and `x86\`, and no
//! `skills/` at all, so a catalog loaded from a directory beside the binary would serve nothing to
//! exactly the installs that have no other way to get these files. And a skill describes the tool
//! surface of a build: compiled in, it is always the one written for the binary answering, where a
//! directory read at startup would serve whatever the checkout holds today against an exe built
//! from some other day's tree. `build.rs` watches every file here for the same reason.
//!
//! **A skill carries the pages it links to.** The playbooks point into this repository's `docs/` —
//! a walkthrough, the session lifecycle, the Secure Kernel research record — and in a plugin install
//! those links resolve, because the plugin *is* the repository. Over MCP a skill is only what its
//! manifest lists, so a page it links to directly is served inside it, at `docs/…` under the skill,
//! and [`relink`] points each link at where its target is served: between two served files, at the
//! other's path inside the skill; to anything else, at that file on GitHub **at this version's
//! release tag** ([`PIN`]), so a deeper link is still one a client can follow. The files on disk are
//! untouched; only what is served is rewritten, and the digests are of what is served. Only one level is bundled, deliberately: the closure of those pages' own
//! links is most of the repository, crash dumps included.
//!
//! **Served per client, by the rule the instructions and descriptions already keep**: nothing
//! model-visible names a tool the client cannot call. A skill is served to a surface only when
//! every tool its files name is one that surface includes, decided by
//! [`crate::toolset::names_tool`] — the predicate those checks assert with — over the text served,
//! bundled pages included. That is why the Secure Kernel playbook is a skill of its own: its tools
//! are an `extra` group the default surface leaves out, and inside `windbg-debugging` it kept that
//! skill from every client but `--tools all`. A skill a surface is not served is absent from both
//! listings and is refused by `skills/get` and `resources/read`, like a tool outside it.
//!
//! **What is not here.** `msrc-patch-diff` stays plugin-only: it drives Binary Ninja far more than
//! this server and ships Python scripts, which a host must hold behind an approval of its own when
//! they arrive over MCP. `resources/directory/read` is not declared — every file is in the
//! manifest, and `resources/read` is the only read the extension requires.

use std::sync::LazyLock;

use rmcp::ErrorData;
use rmcp::model::{
    CacheScope, GetSkillResult, ListResourcesResult, ListSkillsResult, ReadResourceResult,
    Resource, ResourceContents, SKILL_MD, Skill, SkillFrontmatter, SkillResource, SkillResources,
};

use crate::toolset::{Toolset, names_tool};

/// Turns the built-in skills off: no `resources` capability, no skills extension.
///
/// For the Claude Code plugin, which installs the same `skills/` through its own loader. Served
/// twice, a plugin user would see each skill under two names — the plugin's and the plugin
/// server's — with nothing to say which to load. Accepted on stdio only: that is the transport a
/// plugin launches, and a listener has no plugin beside it.
pub const NO_SKILLS_FLAG: &str = "--no-skills";

const SCHEME: &str = "skill://";
const MARKDOWN: &str = "text/markdown";

/// One served file: where it is in this repository, where it is served inside its skill, and its
/// text as it is on disk.
///
/// `include_str!` rather than `include_bytes!`, so a file that is not UTF-8 fails the build instead
/// of reaching `resources/read` as a blob a host has to decode.
struct Source {
    /// Repository-relative, which is where the plugin reads it and what its links are written
    /// against.
    disk: &'static str,
    /// Relative to the skill's root: `skill://<name>/<at>`.
    at: &'static str,
    text: &'static str,
}

/// A file of the skill's own directory, served where it sits.
macro_rules! own {
    ($skill:literal, $at:literal) => {
        Source {
            disk: concat!("skills/", $skill, "/", $at),
            at: $at,
            text: include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/skills/",
                $skill,
                "/",
                $at
            )),
        }
    };
}

/// A page from elsewhere in the repository that the skill links to, served at its repository path
/// inside the skill — `docs/secure-kernel/README.md` is `skill://<name>/docs/secure-kernel/README.md`.
macro_rules! page {
    ($path:literal) => {
        Source {
            disk: $path,
            at: $path,
            text: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/", $path)),
        }
    };
}

/// One served skill: its directory under `skills/`, then every file it serves, `SKILL.md` first.
struct Bundle {
    name: &'static str,
    files: &'static [Source],
}

/// Every skill this server serves and every file of each.
///
/// A list rather than a directory walk, and three tests keep it honest: every file of a served
/// skill's directory is here (`every_file_of_a_served_skill_directory_is_served`), every page those
/// files link to is here (`every_page_a_skill_links_to_is_bundled`), and every path here is a build
/// input (`every_served_file_is_a_build_input`). The bundled pages' own links are not followed —
/// those are served as GitHub URLs.
const SOURCES: &[Bundle] = &[
    Bundle {
        name: "windbg-debugging",
        files: &[
            own!("windbg-debugging", "SKILL.md"),
            own!("windbg-debugging", "crash-dump.md"),
            own!("windbg-debugging", "driver-ioctl.md"),
            own!("windbg-debugging", "heap-walking.md"),
            own!("windbg-debugging", "live-and-kernel.md"),
            own!("windbg-debugging", "setup.md"),
            own!("windbg-debugging", "ttd.md"),
            page!("docs/crash-dump-walkthrough.md"),
            page!("docs/driver-ioctl-walkthrough.md"),
            page!("docs/hevd-ioctl-walkthrough.md"),
        ],
    },
    Bundle {
        name: "windbg-secure-kernel",
        files: &[
            own!("windbg-secure-kernel", "SKILL.md"),
            page!("docs/secure-kernel/sessions.md"),
            page!("docs/secure-kernel/README.md"),
            page!("docs/secure-kernel/kd-facade.md"),
            page!("docs/secure-kernel/m8-debugger.md"),
        ],
    },
];

/// A built-in skill, assembled once: its entry, its `resources/list` row, each file's URI and
/// served text, and the tools they name.
struct Entry {
    skill: Skill,
    listing: Resource,
    files: Vec<(String, String)>,
    names: Vec<&'static str>,
}

impl Entry {
    fn served_to(&self, surface: &Toolset) -> bool {
        self.names.iter().all(|tool| surface.includes(tool))
    }

    fn file(&self, uri: &str) -> Option<&str> {
        self.files
            .iter()
            .find_map(|(at, text)| (at == uri).then_some(text.as_str()))
    }
}

/// Built on first use. A skill that does not assemble is logged and left out rather than taking the
/// server down; the tests below are what keep one from shipping like that.
static CATALOG: LazyLock<Vec<Entry>> = LazyLock::new(|| {
    SOURCES
        .iter()
        .filter_map(|bundle| match assemble(bundle, PIN) {
            Ok(entry) => Some(entry),
            Err(reason) => {
                tracing::error!("not serving the built-in skill {}: {reason}", bundle.name);
                None
            }
        })
        .collect()
});

/// The ref a link to an unserved file is pinned to: this version's release tag, `v0.24.0`.
///
/// **Not the commit**, which it was first, because a host's approval of a skill is bound to the
/// bytes served and every link carries the pin: pinned to the commit, every rebuild was a new
/// version of every skill, and Claude Code asked again after each redeploy with no skill text
/// changed. The tag moves when the version does, which is when a release changes what is served
/// anyway. What it costs is that a build between two releases links a deeper page as the last
/// release had it — the pages a skill links to directly are bundled, and those are always this
/// build's own.
const PIN: &str = concat!("v", env!("CARGO_PKG_VERSION"));

fn assemble(bundle: &Bundle, pin: &str) -> Result<Entry, String> {
    let manifest = bundle.files.first().ok_or("a skill with no files")?;
    if manifest.at != SKILL_MD {
        return Err(format!(
            "{} is listed first and is not its SKILL.md",
            manifest.disk
        ));
    }
    let served: Vec<(String, String)> = bundle
        .files
        .iter()
        .map(|file| {
            (
                format!("{SCHEME}{}/{}", bundle.name, file.at),
                relink(file.text, file, bundle.files, pin),
            )
        })
        .collect();
    let (uri, text) = &served[0];
    let frontmatter = frontmatter(text).map_err(|e| format!("{}: {e}", manifest.disk))?;

    let mut resources: Vec<SkillResource> = served
        .iter()
        .map(|(uri, text)| SkillResource::from_bytes(uri, text.as_bytes()))
        .collect();
    resources.sort_by(|a, b| a.uri.cmp(&b.uri));

    let listing = Resource::new(uri, &frontmatter.name)
        .with_description(&frontmatter.description)
        .with_mime_type(MARKDOWN)
        .with_size(text.len() as u64);
    let skill = Skill::new(uri, frontmatter, SkillResources::Files(resources));
    skill.validate().map_err(|e| e.to_string())?;

    let names = Toolset::every_tool()
        .filter(|tool| served.iter().any(|(_, text)| names_tool(text, tool)))
        .collect();
    Ok(Entry {
        skill,
        listing,
        files: served,
        names,
    })
}

/// `text` as served from `from`: every relative Markdown link pointed at where its target is
/// served. A link between two files this skill serves becomes the path from one to the other inside
/// the skill; a link to anything else in the repository becomes that file on GitHub at `pin`.
/// Absolute URLs and same-page fragments are left alone.
///
/// Only inline `[text](target)` links without a title are rewritten. A relative link in either of
/// the other forms, a reference-style definition or an inline link with a title, would be served
/// as written, which no served file does: `no_served_file_uses_a_link_form_relink_leaves_alone`
/// fails on the first that did, rather than this growing a Markdown parser for forms nobody writes.
fn relink(text: &str, from: &Source, files: &[Source], pin: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("](") {
        let (head, tail) = rest.split_at(open + 2);
        out.push_str(head);
        let Some(close) = tail.find(')') else {
            rest = tail;
            break;
        };
        let target = &tail[..close];
        match retarget(target, from, files, pin) {
            Some(moved) => out.push_str(&moved),
            None => out.push_str(target),
        }
        rest = &tail[close..];
    }
    out.push_str(rest);
    out
}

/// Where one link target should point once served, or `None` to leave it as written.
fn retarget(target: &str, from: &Source, files: &[Source], pin: &str) -> Option<String> {
    if target.is_empty()
        || target.starts_with('#')
        || target.contains("://")
        || target.starts_with("mailto:")
        || target.contains(char::is_whitespace)
    {
        return None;
    }
    let (path, fragment) = target.split_at(target.find('#').unwrap_or(target.len()));
    let resolved = resolve(parent(from.disk), path)?;
    if let Some(to) = files.iter().find(|file| file.disk == resolved) {
        return Some(format!("{}{fragment}", relative(parent(from.at), to.at)));
    }
    let repository = env!("CARGO_PKG_REPOSITORY");
    Some(format!("{repository}/blob/{pin}/{resolved}{fragment}"))
}

/// The directory part of a `/`-separated relative path; `""` for a file at the root.
fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// `path` resolved against the directory `base`, both repository-relative, with `.` and `..`
/// applied — or `None` for a path that climbs out of the repository or names nothing.
fn resolve(base: &str, path: &str) -> Option<String> {
    let mut segments: Vec<&str> = if path.starts_with('/') {
        Vec::new()
    } else {
        base.split('/').filter(|s| !s.is_empty()).collect()
    };
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            name => segments.push(name),
        }
    }
    (!segments.is_empty()).then(|| segments.join("/"))
}

/// The relative path from the directory `from` to the file `to`, both relative to one root.
fn relative(from: &str, to: &str) -> String {
    let from: Vec<&str> = from.split('/').filter(|s| !s.is_empty()).collect();
    let to: Vec<&str> = to.split('/').collect();
    let shared = from
        .iter()
        .zip(&to[..to.len() - 1])
        .take_while(|(a, b)| a == b)
        .count();
    let mut path: Vec<&str> = std::iter::repeat_n("..", from.len() - shared).collect();
    path.extend(&to[shared..]);
    path.join("/")
}

/// A `SKILL.md`'s frontmatter, read under a deliberately narrow grammar: `name` and `description`,
/// each once, each a one-line YAML plain scalar.
///
/// Not a YAML parser, and it does not have to be one: the spec wants the frontmatter as JSON
/// *verbatim*, so the only failure that matters is reading a value differently from how YAML would.
/// This refuses whatever it cannot be sure about — another key, a quote, a block scalar, a `: `
/// inside a value — rather than guessing, and `the_served_catalog_is_what_rmcp_loads_from_it`
/// checks what it accepts against rmcp's own reader, which is a YAML parser.
fn frontmatter(text: &str) -> Result<SkillFrontmatter, String> {
    let mut lines = text.lines();
    if lines.next() != Some("---") {
        return Err("does not open with a `---` frontmatter block".into());
    }
    let (mut name, mut description) = (None, None);
    for line in lines {
        if line == "---" {
            return match (name, description) {
                (Some(name), Some(description)) => Ok(SkillFrontmatter::new(name, description)),
                _ => Err("frontmatter needs both `name` and `description`".into()),
            };
        }
        let (key, value) = line
            .split_once(": ")
            .ok_or_else(|| format!("frontmatter line `{line}` is not `key: value`"))?;
        let slot = match key {
            "name" => &mut name,
            "description" => &mut description,
            other => {
                return Err(format!(
                    "frontmatter key `{other}` is not one this reader takes"
                ));
            }
        };
        if !plain(value) {
            return Err(format!("`{key}` is not a one-line plain scalar"));
        }
        if slot.replace(value).is_some() {
            return Err(format!("`{key}` is given twice"));
        }
    }
    Err("frontmatter block is never closed".into())
}

/// Whether a value on one line is a YAML plain scalar meaning exactly its own text.
fn plain(value: &str) -> bool {
    const INDICATORS: &[char] = &[
        '-', '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@',
        '`',
    ];
    !value.is_empty()
        && value.trim() == value
        && !value.starts_with(INDICATORS)
        && !value.contains(": ")
        && !value.contains(" #")
        && !value.ends_with(':')
}

/// Whether this surface is served any built-in skill — which is what decides whether the
/// `resources` capability and the skills extension are declared at all.
pub fn any(surface: &Toolset) -> bool {
    CATALOG.iter().any(|entry| entry.served_to(surface))
}

/// `skills/list`: every skill this surface is served, on one page.
///
/// **Cacheable by this client only**, and said here rather than left to rmcp's default (which is
/// the same answer today): what a listing holds depends on the caller's surface, so a cache shared
/// between clients — an intermediary in front of a listener — would hand one client's catalog to
/// another. The same goes for every answer below.
pub fn list(surface: &Toolset) -> ListSkillsResult {
    let mut result = ListSkillsResult::with_all_items(
        CATALOG
            .iter()
            .filter(|entry| entry.served_to(surface))
            .map(|entry| entry.skill.clone())
            .collect(),
    );
    result.cache_scope = Some(CacheScope::Private);
    result
}

/// `skills/get`. `-32602` for a URI that is not a skill here, and for one this surface is not
/// served, the second carrying `widening`'s remedy, since what to change is the surface and not
/// the URI. That remedy is the tool refusal's own: on a listener a client's surface may be its
/// credential's rather than the run's, and only the caller knows which.
pub fn get(
    surface: &Toolset,
    uri: &str,
    widening: impl FnOnce() -> String,
) -> Result<GetSkillResult, ErrorData> {
    let entry = CATALOG
        .iter()
        .find(|entry| entry.skill.uri == uri)
        .ok_or_else(|| ErrorData::invalid_params(format!("no skill is served at {uri}"), None))?;
    if !entry.served_to(surface) {
        return Err(ErrorData::invalid_params(
            format!(
                "{uri} is not served to this client: it names tools outside this client's tool \
                 surface. {}",
                widening()
            ),
            None,
        ));
    }
    Ok(GetSkillResult::new(entry.skill.clone()).with_cache_scope(CacheScope::Private))
}

/// `resources/list`: the `SKILL.md` of every skill this surface is served, as rmcp's own catalog
/// lists them. Supporting files are in each skill's manifest instead.
pub fn resources(surface: &Toolset) -> ListResourcesResult {
    let mut result = ListResourcesResult::with_all_items(
        CATALOG
            .iter()
            .filter(|entry| entry.served_to(surface))
            .map(|entry| entry.listing.clone())
            .collect(),
    );
    result.cache_scope = Some(CacheScope::Private);
    result
}

/// `resources/read` of a skill file, or `None` when this surface is served no file at `uri`.
pub fn read(surface: &Toolset, uri: &str) -> Option<ReadResourceResult> {
    let text = CATALOG
        .iter()
        .filter(|entry| entry.served_to(surface))
        .find_map(|entry| entry.file(uri))?;
    let mut result = ReadResourceResult::new(vec![
        ResourceContents::text(text, uri).with_mime_type(MARKDOWN),
    ]);
    result.cache_scope = Some(CacheScope::Private);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rmcp::handler::server::skill_catalog::SkillCatalog;

    /// Skills under `skills/` that this server deliberately does not serve. Every directory there
    /// is either in [`SOURCES`] or here, so a new one is a decision rather than an omission.
    const PLUGIN_ONLY: &[&str] = &["msrc-patch-diff"];

    /// A pin for the relinking tests, so they say the same thing whatever version this is.
    const TAG: &str = "v0.0.0";

    fn repo() -> &'static std::path::Path {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    fn surface(spec: &str) -> Toolset {
        Toolset::parse(spec).unwrap_or_else(|e| panic!("`{spec}` should parse: {e}"))
    }

    fn served(spec: &str) -> Vec<String> {
        list(&surface(spec))
            .skills
            .into_iter()
            .map(|skill| skill.frontmatter.name)
            .collect()
    }

    /// Every inline link target in `text`, in order.
    fn targets(text: &str) -> Vec<&str> {
        text.match_indices("](")
            .filter_map(|(at, _)| {
                let tail = &text[at + 2..];
                tail.find(')').map(|close| &tail[..close])
            })
            .collect()
    }

    #[test]
    fn every_built_in_skill_assembles() {
        assert_eq!(CATALOG.len(), SOURCES.len());
    }

    /// **The differential check.** What this server serves, written out as a skills directory,
    /// must be exactly what rmcp's own loader reads back from it: the same URIs, the same
    /// frontmatter, the same digest and size for every file, the same `resources/list` rows and the
    /// same text from `resources/read`. rmcp parses frontmatter as YAML, so this is what catches a
    /// value [`frontmatter`] reads differently from YAML; and it validates every entry, so a
    /// manifest the spec would refuse fails here rather than in a host.
    #[test]
    fn the_served_catalog_is_what_rmcp_loads_from_it() {
        let staging =
            std::env::temp_dir().join(format!("windbg-mcp-skills-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&staging);
        for (bundle, entry) in SOURCES.iter().zip(CATALOG.iter()) {
            for ((_, text), file) in entry.files.iter().zip(bundle.files) {
                let path = staging.join(bundle.name).join(file.at);
                std::fs::create_dir_all(path.parent().expect("a file has a directory"))
                    .expect("create the staging directory");
                std::fs::write(&path, text).expect("write a served file");
            }
        }
        let oracle = SkillCatalog::from_dir(&staging).expect("rmcp loads the staged skills");
        let everything = surface("all");

        let ours: Vec<Skill> = CATALOG.iter().map(|e| e.skill.clone()).collect();
        assert_eq!(
            ours,
            oracle.skills(),
            "skills/list differs from rmcp's loader"
        );
        assert_eq!(
            resources(&everything).resources,
            oracle.resources(),
            "resources/list differs from rmcp's loader"
        );
        for entry in CATALOG.iter() {
            for (uri, _) in &entry.files {
                assert_eq!(
                    read(&everything, uri).map(|r| r.contents),
                    oracle.read_resource(uri).map(|r| r.contents),
                    "resources/read of {uri} differs from rmcp's loader"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&staging);
    }

    /// Every skill directory is either served or named as plugin-only, and nothing is both.
    #[test]
    fn every_skill_directory_is_served_or_plugin_only() {
        let served: Vec<&str> = SOURCES.iter().map(|bundle| bundle.name).collect();
        let mut on_disk: Vec<String> = std::fs::read_dir(repo().join("skills"))
            .expect("skills/ is readable")
            .map(|entry| entry.expect("a readable entry"))
            .filter(|entry| entry.path().join(SKILL_MD).is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        on_disk.sort();
        let mut decided: Vec<String> = served
            .iter()
            .chain(PLUGIN_ONLY)
            .map(|name| name.to_string())
            .collect();
        decided.sort();
        assert_eq!(on_disk, decided);
        assert!(served.iter().all(|name| !PLUGIN_ONLY.contains(name)));
    }

    /// A file added to a served skill's directory and not to [`SOURCES`] would be linked from its
    /// `SKILL.md` and never served, so the directory and the table must agree, file for file.
    #[test]
    fn every_file_of_a_served_skill_directory_is_served() {
        for bundle in SOURCES {
            let root = repo().join("skills").join(bundle.name);
            let mut on_disk = Vec::new();
            let mut pending = vec![root.clone()];
            while let Some(dir) = pending.pop() {
                for entry in std::fs::read_dir(&dir).expect("a readable skill directory") {
                    let path = entry.expect("a readable entry").path();
                    let name = path
                        .file_name()
                        .expect("an entry has a name")
                        .to_string_lossy();
                    if name.starts_with('.') {
                        continue;
                    }
                    if path.is_dir() {
                        pending.push(path);
                    } else {
                        let at = path.strip_prefix(&root).expect("below the skill");
                        on_disk.push(at.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
            on_disk.sort();
            let mut listed: Vec<String> = bundle
                .files
                .iter()
                .filter(|file| file.disk.starts_with("skills/"))
                .map(|file| file.at.to_string())
                .collect();
            listed.sort();
            assert_eq!(
                on_disk, listed,
                "skills/{} and SOURCES disagree",
                bundle.name
            );
        }
    }

    /// What is compiled in has to be a build input, or a build serving a changed page reports the
    /// identity of one that did not. `build.rs` is a separate crate and its `INPUTS` cannot be
    /// imported, so the list is read out of its source.
    #[test]
    fn every_served_file_is_a_build_input() {
        let build = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/build.rs"));
        let start = build
            .find("const INPUTS")
            .expect("build.rs declares INPUTS");
        let list = &build[start..];
        let list = &list[list.find('[').expect("an array")..];
        let list = &list[..list.find("];").expect("the array closes")];
        let list = &list[list.find('=').map_or(0, |at| at + 1)..];
        let inputs: Vec<&str> = list.split('"').skip(1).step_by(2).collect();
        assert!(inputs.contains(&"src"), "read INPUTS wrongly: {inputs:?}");
        for file in SOURCES.iter().flat_map(|bundle| bundle.files) {
            assert!(
                inputs
                    .iter()
                    .any(|input| file.disk == *input || file.disk.starts_with(&format!("{input}/"))),
                "{} is compiled in and is not under any of build.rs's INPUTS {inputs:?}",
                file.disk
            );
        }
    }

    /// The point of bundling the pages: over MCP, a relative link a served file carries lands on a
    /// file the skill serves. Read off the **served** text with the link resolved the way a host
    /// resolves it, against the file's own place in the skill — so a link [`relink`] missed, or a
    /// page a skill links to and [`SOURCES`] does not bundle, fails here by name.
    #[test]
    fn no_served_link_points_outside_what_is_served() {
        for bundle in SOURCES {
            let served: Vec<&str> = bundle.files.iter().map(|file| file.at).collect();
            for file in bundle.files {
                let text = relink(file.text, file, bundle.files, TAG);
                for target in targets(&text) {
                    if target.is_empty()
                        || target.starts_with('#')
                        || target.contains("://")
                        || target.contains(char::is_whitespace)
                    {
                        continue;
                    }
                    let path = &target[..target.find('#').unwrap_or(target.len())];
                    let lands = resolve(parent(file.at), path);
                    assert!(
                        lands.as_deref().is_some_and(|at| served.contains(&at)),
                        "{} serves a link to `{target}`, which lands on {lands:?} and not on a file \
                         {} serves",
                        file.disk,
                        bundle.name
                    );
                }
            }
        }
    }

    /// **One level is bundled, and this is what says it is the whole level**: every relative link in
    /// a skill's own files reaches a file the skill serves. The test above cannot say that — a page
    /// left out of [`SOURCES`] is served as a GitHub URL, which it skips — and it is the property
    /// the bundling is for: what a playbook points at is in the skill, not behind a web fetch.
    #[test]
    fn every_page_a_skill_links_to_is_bundled() {
        for bundle in SOURCES {
            let served: Vec<&str> = bundle.files.iter().map(|file| file.disk).collect();
            for file in bundle
                .files
                .iter()
                .filter(|f| f.disk.starts_with("skills/"))
            {
                for target in targets(file.text) {
                    if target.is_empty()
                        || target.starts_with('#')
                        || target.contains("://")
                        || target.contains(char::is_whitespace)
                    {
                        continue;
                    }
                    let path = &target[..target.find('#').unwrap_or(target.len())];
                    let lands = resolve(parent(file.disk), path);
                    assert!(
                        lands.as_deref().is_some_and(|disk| served.contains(&disk)),
                        "{} links to `{target}` ({lands:?}), which {} does not bundle",
                        file.disk,
                        bundle.name
                    );
                }
            }
        }
    }

    /// The two Markdown link forms [`relink`] does not rewrite, refused rather than supported: a
    /// relative inline link with a title, and a relative reference-style definition. Either would
    /// be served pointing where the file sits on disk, and both link checks above would pass it,
    /// since they read inline targets and skip one with a title in it.
    #[test]
    fn no_served_file_uses_a_link_form_relink_leaves_alone() {
        let relative = |target: &str| {
            !target.is_empty()
                && !target.starts_with('#')
                && !target.contains("://")
                && !target.starts_with("mailto:")
        };
        // A title is a quoted string, or a parenthesised one, that ends the link: `setup.md`'s
        // PowerShell `[xml](Get-Content "…" -Raw)` cast has a quote in it and is not a link.
        let titled = |text: &str| -> Vec<String> {
            targets(text)
                .into_iter()
                .filter(|target| {
                    let Some((path, title)) = target.split_once(char::is_whitespace) else {
                        return false;
                    };
                    let title = title.trim();
                    let closed = |quote: char| {
                        title.len() >= 2 && title.starts_with(quote) && title.ends_with(quote)
                    };
                    relative(path) && (closed('"') || closed('\'') || title.starts_with('('))
                })
                .map(str::to_string)
                .collect()
        };
        let definitions = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|line| line.len() - line.trim_start().len() <= 3)
                .filter_map(|line| {
                    let line = line.trim_start().strip_prefix('[')?;
                    let (label, rest) = line.split_once("]:")?;
                    let target = rest.split_whitespace().next()?;
                    (!label.contains(']') && relative(target)).then(|| target.to_string())
                })
                .collect()
        };
        for file in SOURCES.iter().flat_map(|bundle| bundle.files) {
            let found: Vec<String> = titled(file.text)
                .into_iter()
                .chain(definitions(file.text))
                .collect();
            assert!(
                found.is_empty(),
                "{} has relative links relink serves unchanged: {found:?}",
                file.disk
            );
        }
        // And the check sees both forms, so its silence above means something.
        assert_eq!(
            titled(r#"[a](../x.md "t") [b](https://e.com "t") [xml](Get-Content "$w\x" -Raw)"#),
            [r#"../x.md "t""#]
        );
        assert_eq!(
            definitions("[a]: ../x.md\n[b]: https://e.com\n    [c]: ../y.md"),
            ["../x.md"]
        );
    }

    /// And the links are the **only** thing served differently from the file on disk.
    #[test]
    fn relinking_changes_link_targets_and_nothing_else() {
        let blank = |text: &str| {
            let mut out = text.to_string();
            for target in targets(text) {
                out = out.replacen(&format!("]({target})"), "]()", 1);
            }
            out
        };
        for bundle in SOURCES {
            for file in bundle.files {
                let served = relink(file.text, file, bundle.files, TAG);
                assert_eq!(blank(&served), blank(file.text), "{}", file.disk);
            }
        }
    }

    #[test]
    fn a_link_is_pointed_at_where_its_target_is_served() {
        let files = [
            Source {
                disk: "skills/s/SKILL.md",
                at: "SKILL.md",
                text: "",
            },
            Source {
                disk: "skills/s/setup.md",
                at: "setup.md",
                text: "",
            },
            Source {
                disk: "docs/a/page.md",
                at: "docs/a/page.md",
                text: "",
            },
        ];
        let [skill, _, page] = &files;
        let from = |source: &Source, text: &str| relink(text, source, &files, TAG);
        let repository = env!("CARGO_PKG_REPOSITORY");

        // Into a bundled page, with its fragment.
        assert_eq!(
            from(skill, "[p](../../docs/a/page.md#part)"),
            "[p](docs/a/page.md#part)"
        );
        // Back out of a page into the skill's own files.
        assert_eq!(
            from(page, "see [setup](../../skills/s/setup.md)."),
            "see [setup](../../setup.md)."
        );
        // A sibling is already right.
        assert_eq!(from(skill, "[s](setup.md)"), "[s](setup.md)");
        // Anything else in the repository goes to GitHub at the pin.
        assert_eq!(
            from(page, "[r](../../README.md#top)"),
            format!("[r]({repository}/blob/{TAG}/README.md#top)")
        );
        // Absolute links, fragments, titles and paths that climb out of the repository are left alone.
        for kept in [
            "[x](https://example.com/a)",
            "[x](#below)",
            "[x](../../README.md \"title\")",
            "[x](../../../../outside.md)",
        ] {
            assert_eq!(from(page, kept), kept);
        }
    }

    /// **What is served depends on the version and not on the commit**, which is the property the
    /// pin exists for: a host binds its approval of a skill to the served bytes, so a pin that moved
    /// with every commit made every rebuild a new version of every skill. Asserted on the served
    /// text rather than on [`PIN`]'s spelling, because the leak would be a build stamp reaching a
    /// link however it got there.
    #[test]
    fn a_served_skill_carries_no_build_stamp() {
        // `g<short sha>`, optionally `-dirty.<digest>`; nothing at all where build.rs had no git.
        let commit = env!("WINDBG_MCP_BUILD")
            .strip_prefix('g')
            .and_then(|stamp| stamp.split('-').next())
            .filter(|sha| sha.len() >= 7);
        for entry in CATALOG.iter() {
            for (uri, text) in &entry.files {
                if let Some(sha) = commit {
                    assert!(
                        !text.contains(&format!("/blob/{sha}")),
                        "{uri} links a page at this build's commit {sha}"
                    );
                }
            }
        }
        assert_eq!(PIN, concat!("v", env!("CARGO_PKG_VERSION")));
    }

    /// Which client gets which skill. The default surface is the case the split was for: it gets
    /// `windbg-debugging` and not the Secure Kernel playbook, whose tools it cannot call.
    #[test]
    fn a_skill_is_served_only_where_every_tool_it_names_is() {
        assert_eq!(served("all"), ["windbg-debugging", "windbg-secure-kernel"]);
        assert_eq!(
            list(&Toolset::default())
                .skills
                .iter()
                .map(|s| s.name())
                .collect::<Vec<_>>(),
            ["windbg-debugging"]
        );
        // The Secure Kernel playbook names the generic tools its M8 route drives as well, so the
        // group alone is not enough to be served it.
        assert!(served("securekernel").is_empty());
        assert_eq!(
            served("securekernel,inspect,exec"),
            ["windbg-secure-kernel"]
        );
        // A narrowed surface is served nothing rather than a playbook full of refusals.
        assert!(served("crash").is_empty());
        assert!(!any(&surface("crash")));
    }

    /// The property itself, checked from the other end: whatever a surface is served, no file of it
    /// names a tool that surface does not include.
    #[test]
    fn no_served_skill_names_a_tool_the_client_cannot_call() {
        for spec in [
            "all",
            "crash",
            "session,inspect,crash",
            "securekernel",
            "securekernel,inspect,exec",
            "ttd",
        ] {
            let surface = surface(spec);
            for entry in CATALOG.iter().filter(|e| e.served_to(&surface)) {
                for (uri, text) in &entry.files {
                    for tool in Toolset::every_tool().filter(|t| !surface.includes(t)) {
                        assert!(
                            !names_tool(text, tool),
                            "`--tools {spec}` is served {uri}, which names `{tool}`"
                        );
                    }
                }
            }
        }
        let default = Toolset::default();
        for entry in CATALOG.iter().filter(|e| e.served_to(&default)) {
            for (uri, text) in &entry.files {
                for tool in Toolset::every_tool().filter(|t| !default.includes(t)) {
                    assert!(
                        !names_tool(text, tool),
                        "the default surface is served {uri}, which names `{tool}`"
                    );
                }
            }
        }
    }

    #[test]
    fn a_skill_outside_the_surface_is_refused_and_unreadable() {
        let crash = surface("crash");
        let uri = "skill://windbg-debugging/SKILL.md";
        let widen = |chosen| move || Toolset::widening("bench", chosen);
        let refused = get(&crash, uri, widen(crate::toolset::Chosen::ForTheRun))
            .expect_err("`crash` is not served windbg-debugging");
        assert_eq!(refused.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(refused.message.contains("--tools"), "{}", refused.message);
        // A listener client whose surface is its own credential's is pointed at that, not at the
        // run's `--tools`, which would change nothing for it.
        let refused = get(&crash, uri, widen(crate::toolset::Chosen::ForThisClient))
            .expect_err("`crash` is not served windbg-debugging");
        assert!(
            refused.message.contains(crate::client::TOOLS_ENV) && refused.message.contains("bench"),
            "{}",
            refused.message
        );
        assert!(read(&crash, uri).is_none());
        assert!(resources(&crash).resources.is_empty());

        let unknown = get(
            &Toolset::default(),
            "skill://nothing-here/SKILL.md",
            widen(crate::toolset::Chosen::ForTheRun),
        )
        .expect_err("no such skill");
        assert_eq!(unknown.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(!unknown.message.contains("--tools"), "{}", unknown.message);
    }

    #[test]
    fn the_frontmatter_reader_refuses_what_it_cannot_be_sure_of() {
        let ok = "---\nname: a-skill\ndescription: Does a thing, with `code` in it.\n---\nbody";
        let read = frontmatter(ok).expect("two plain scalars");
        assert_eq!(
            read,
            SkillFrontmatter::new("a-skill", "Does a thing, with `code` in it.")
        );

        for (bad, why) in [
            ("name: a\ndescription: b\n---\n", "no opening fence"),
            ("---\nname: a\ndescription: b\n", "no closing fence"),
            ("---\nname: a\n---\n", "no description"),
            (
                "---\nname: a\nname: b\ndescription: c\n---\n",
                "a repeated key",
            ),
            (
                "---\nname: a\ndescription: b\nlicense: MIT\n---\n",
                "a key it does not take",
            ),
            (
                "---\nname: a\ndescription: \"quoted\"\n---\n",
                "a quoted scalar",
            ),
            (
                "---\nname: a\ndescription: >\n  folded\n---\n",
                "a block scalar",
            ),
            (
                "---\nname: a\ndescription: x: y\n---\n",
                "a mapping indicator inside",
            ),
            ("---\nname: a\ndescription: x #y\n---\n", "a comment"),
        ] {
            assert!(frontmatter(bad).is_err(), "accepted {why}: {bad:?}");
        }
    }
}
