//! Exact-build manifest for the first M6 Secure Kernel service trace.
//!
//! M6.0 deliberately lands the checked data and its refusal logic before the live recorder. The
//! recorder added by M6.1 must pass its observed identity and guarded reads through this module
//! before it changes a debug register. Keeping the JSON outside Rust gives qualification one
//! source of constants; these types and tests consume it rather than restating its RVAs or layout.

#![allow(dead_code)] // Consumed by M6.1; M6.0 lands and tests the gate before exposing a tool.

use std::collections::HashSet;
use std::fmt::Display;

use iced_x86::{Decoder, DecoderOptions};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const MANIFEST_JSON: &str =
    include_str!("../docs/secure-kernel/manifests/securekernel-10.0.26100.9457-service-47.json");
const SCHEMA: &str = "windbg-mcp.sk-service-manifest.v1";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceManifest {
    pub(crate) schema: String,
    pub(crate) manifest_id: String,
    pub(crate) image: ImageIdentity,
    pub(crate) service: Service,
    pub(crate) sites: Vec<Site>,
    pub(crate) static_guards: Vec<StaticGuard>,
    pub(crate) request_layout: Layout,
    pub(crate) capture: Capture,
    pub(crate) cardinality: Cardinality,
    pub(crate) hardware_slots_required: u8,
    pub(crate) qualification: Qualification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImageIdentity {
    pub(crate) module: String,
    pub(crate) original_filename: String,
    pub(crate) file_version: String,
    pub(crate) file_size: u64,
    pub(crate) sha256: String,
    pub(crate) pe: PeIdentity,
    pub(crate) pdb: PdbIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeIdentity {
    pub(crate) machine: u16,
    pub(crate) sections: u16,
    pub(crate) timestamp: u32,
    pub(crate) size_of_image: u32,
    pub(crate) checksum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PdbIdentity {
    pub(crate) guid: String,
    pub(crate) age: u32,
    pub(crate) key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Service {
    pub(crate) number: u32,
    pub(crate) caller_symbol: String,
    pub(crate) handler_symbol: String,
    pub(crate) handler_rva: u32,
    pub(crate) handler_call_rva: u32,
    pub(crate) number_source: NumberSource,
    pub(crate) status_source: StatusSource,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NumberSource {
    pub(crate) phase: String,
    pub(crate) base_register: String,
    pub(crate) offset: u32,
    pub(crate) width: u32,
    pub(crate) byte_order: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusSource {
    pub(crate) phase: String,
    pub(crate) register: String,
    pub(crate) width: u32,
    pub(crate) encoding: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Site {
    pub(crate) phase: String,
    pub(crate) symbol: String,
    pub(crate) rva: u32,
    pub(crate) slot: u8,
    pub(crate) guard: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StaticGuard {
    pub(crate) name: String,
    pub(crate) rva: u32,
    pub(crate) guard: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Layout {
    pub(crate) size: u32,
    pub(crate) alignment: u32,
    pub(crate) fields: Vec<Field>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) offset: u32,
    pub(crate) width: u32,
    pub(crate) alignment: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capture {
    pub(crate) per_buffer_limit_max: u32,
    pub(crate) regions: Vec<Region>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Region {
    pub(crate) name: String,
    pub(crate) entry_base_register: String,
    pub(crate) dispatch_base_register: String,
    pub(crate) offset: u32,
    pub(crate) length: u32,
    pub(crate) alignment: u32,
    pub(crate) before: bool,
    pub(crate) after: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cardinality {
    pub(crate) positive_stage: String,
    pub(crate) selected_calls_per_positive_ordinal: u32,
    pub(crate) negative_stage: String,
    pub(crate) selected_calls_per_negative_ordinal: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Qualification {
    pub(crate) status: String,
    pub(crate) date: String,
    pub(crate) positive_runs: Vec<String>,
    pub(crate) negative_runs: Vec<String>,
    pub(crate) dropped: u32,
    pub(crate) unreadable: u32,
    pub(crate) retained_processes: u32,
}

/// Identity supplied by a live opener before the first guarded write.
#[derive(Debug)]
pub(crate) struct ObservedImageIdentity<'a> {
    pub(crate) module: &'a str,
    pub(crate) file_version: &'a str,
    pub(crate) file_size: u64,
    pub(crate) sha256: &'a str,
    pub(crate) machine: u16,
    pub(crate) sections: u16,
    pub(crate) timestamp: u32,
    pub(crate) size_of_image: u32,
    pub(crate) checksum: u32,
    pub(crate) pdb_guid: &'a str,
    pub(crate) pdb_age: u32,
}

/// Identity proved from the image mapped in VTL1. File size, version and SHA-256 remain the
/// provenance of the manifest's pinned disk image; the running-image proof is its PE identity,
/// CodeView/PDB identity and complete guarded byte set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveImageProof {
    pub(crate) machine: u16,
    pub(crate) sections: u16,
    pub(crate) timestamp: u32,
    pub(crate) size_of_image: u32,
    pub(crate) checksum: u32,
    pub(crate) pdb_guid: String,
    pub(crate) pdb_age: u32,
}

pub(crate) fn service_manifest() -> Result<ServiceManifest, String> {
    let manifest: ServiceManifest = serde_json::from_str(MANIFEST_JSON)
        .map_err(|error| format!("M6 service manifest is not valid JSON: {error}"))?;
    manifest.validate()?;
    Ok(manifest)
}

impl ServiceManifest {
    /// Reject a malformed or internally inconsistent manifest without reading a target.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err(format!(
                "unsupported M6 service manifest schema: {}",
                self.schema
            ));
        }
        if self.manifest_id.is_empty() || self.image.module.is_empty() {
            return Err("manifest and image names must not be empty".into());
        }
        if decode_hex("image sha256", &self.image.sha256)?.len() != 32 {
            return Err("image sha256 must contain exactly 32 bytes".into());
        }
        if decode_hex("PDB guid", &self.image.pdb.guid)?.len() != 16 {
            return Err("PDB guid must contain exactly 16 bytes".into());
        }
        let pdb_key = format!("{}{:X}", self.image.pdb.guid, self.image.pdb.age);
        if self.image.pdb.key != pdb_key {
            return Err("PDB key does not agree with its guid and age".into());
        }
        if self.service.number > u16::MAX as u32 {
            return Err("service number does not fit its declared 16-bit source".into());
        }
        if self.hardware_slots_required == 0 || self.hardware_slots_required > 4 {
            return Err("M6 requires from one through four hardware slots".into());
        }
        if self.sites.len() != self.hardware_slots_required as usize {
            return Err("hardware slot count does not equal the guarded live-site count".into());
        }

        let expected_phases = ["entry", "dispatch", "return"];
        let mut slots = HashSet::new();
        let mut site_rvas = HashSet::new();
        for (site, expected) in self.sites.iter().zip(expected_phases) {
            if site.phase != expected {
                return Err(format!("expected {expected} site, found {}", site.phase));
            }
            if site.symbol.is_empty() || !slots.insert(site.slot) {
                return Err("live sites need nonempty symbols and unique slots".into());
            }
            if site.slot >= self.hardware_slots_required || !site_rvas.insert(site.rva) {
                return Err("live site has an out-of-range slot or duplicate RVA".into());
            }
            guard_in_image(&self.image, &site.phase, site.rva, &site.guard)?;
        }

        let mut static_names = HashSet::new();
        for guard in &self.static_guards {
            if guard.name.is_empty() || !static_names.insert(&guard.name) {
                return Err("static guards need unique nonempty names".into());
            }
            guard_in_image(&self.image, &guard.name, guard.rva, &guard.guard)?;
        }

        let entry = self.site("entry")?;
        let dispatch = self.site("dispatch")?;
        let returned = self.site("return")?;
        if self.service.number_source.phase != dispatch.phase
            || self.service.status_source.phase != returned.phase
            || self.service.number_source.byte_order != "little"
        {
            return Err(
                "service or status source is bound to the wrong phase or byte order".into(),
            );
        }
        let service_field = self
            .request_layout
            .fields
            .iter()
            .find(|field| field.name == "service_number")
            .ok_or_else(|| "request layout has no service_number field".to_string())?;
        if service_field.offset != self.service.number_source.offset
            || service_field.width != self.service.number_source.width
        {
            return Err("service source and request layout disagree".into());
        }
        if self.service.number_source.base_register != "r14"
            || self.service.number_source.width != 2
            || self.service.status_source.register != "eax"
            || self.service.status_source.width != 4
            || self.service.status_source.encoding != "ntstatus"
        {
            return Err("first-service register contract changed".into());
        }
        let service_load = self.static_guard("service-number-load")?;
        let load = decode_hex("service-number-load guard", &service_load.guard)?;
        let offset = u8::try_from(self.service.number_source.offset).map_err(|_| {
            "service-number offset does not fit its guarded instruction".to_string()
        })?;
        if load.get(..5) != Some([0x41, 0x0f, 0xb7, 0x7e, offset].as_slice()) {
            return Err("service-number load does not match r14 plus the declared offset".into());
        }

        let dispatch_bytes = decode_hex("dispatch guard", &dispatch.guard)?;
        let call_offset = self
            .service
            .handler_call_rva
            .checked_sub(dispatch.rva)
            .ok_or_else(|| "handler call precedes the dispatch site".to_string())?
            as usize;
        let call = dispatch_bytes
            .get(call_offset..call_offset + 5)
            .ok_or_else(|| "dispatch guard does not cover the handler call".to_string())?;
        if call[0] != 0xe8 || self.service.handler_call_rva + 5 != returned.rva {
            return Err("selected handler call and return site are not one guarded call".into());
        }
        let displacement = i32::from_le_bytes(call[1..5].try_into().expect("four-byte slice"));
        let target = i64::from(self.service.handler_call_rva) + 5 + i64::from(displacement);
        if target != i64::from(self.service.handler_rva) {
            return Err("guarded call does not target the declared service handler".into());
        }
        if entry.rva >= self.image.pe.size_of_image
            || self.service.handler_rva >= self.image.pe.size_of_image
        {
            return Err("entry or service handler lies outside the image".into());
        }

        validate_layout(&self.request_layout)?;
        if self.capture.per_buffer_limit_max != 4096 || self.capture.regions.is_empty() {
            return Err("capture must retain the 0-through-4096 byte contract".into());
        }
        let mut region_names = HashSet::new();
        for region in &self.capture.regions {
            let end = region
                .offset
                .checked_add(region.length)
                .ok_or_else(|| format!("capture region {} wraps", region.name))?;
            if region.name.is_empty()
                || !region_names.insert(&region.name)
                || region.alignment == 0
                || !region.alignment.is_power_of_two()
                || !region.offset.is_multiple_of(region.alignment)
                || end > self.request_layout.size
                || region.length > self.capture.per_buffer_limit_max
                || (!region.before && !region.after)
                || region.entry_base_register.is_empty()
                || region.dispatch_base_register.is_empty()
                || region.entry_base_register != "rcx"
                || region.dispatch_base_register != "r14"
            {
                return Err(format!("invalid capture region {}", region.name));
            }
        }
        if self.cardinality.selected_calls_per_positive_ordinal == 0
            || self.cardinality.selected_calls_per_negative_ordinal != 0
            || self.cardinality.positive_stage == self.cardinality.negative_stage
        {
            return Err("positive and negative workload cardinalities are not separated".into());
        }
        if self.qualification.status != "passed"
            || self.qualification.positive_runs.len() < 3
            || self.qualification.negative_runs.len() < 3
            || self.qualification.dropped != 0
            || self.qualification.unreadable != 0
            || self.qualification.retained_processes != 0
        {
            return Err("M6.0 qualification evidence is incomplete".into());
        }
        Ok(())
    }

    pub(crate) fn verify_identity(
        &self,
        observed: &ObservedImageIdentity<'_>,
    ) -> Result<(), String> {
        let expected = &self.image;
        let same = observed.module == expected.module
            && observed.file_version == expected.file_version
            && observed.file_size == expected.file_size
            && observed.sha256.eq_ignore_ascii_case(&expected.sha256)
            && observed.machine == expected.pe.machine
            && observed.sections == expected.pe.sections
            && observed.timestamp == expected.pe.timestamp
            && observed.size_of_image == expected.pe.size_of_image
            && observed.checksum == expected.pe.checksum
            && observed.pdb_guid.eq_ignore_ascii_case(&expected.pdb.guid)
            && observed.pdb_age == expected.pdb.age;
        same.then_some(())
            .ok_or_else(|| "observed Secure Kernel identity does not match the M6 manifest".into())
    }

    /// Read and compare every live and static guard. The caller supplies target reads; this method
    /// performs no mutation and therefore belongs before the debug-register transaction.
    pub(crate) fn verify_guards<F, E>(&self, mut read: F) -> Result<(), String>
    where
        F: FnMut(u32, usize) -> Result<Vec<u8>, E>,
        E: Display,
    {
        for (name, rva, encoded) in self
            .sites
            .iter()
            .map(|site| (site.phase.as_str(), site.rva, site.guard.as_str()))
            .chain(
                self.static_guards
                    .iter()
                    .map(|guard| (guard.name.as_str(), guard.rva, guard.guard.as_str())),
            )
        {
            let expected = decode_hex(name, encoded)?;
            let actual = read(rva, expected.len())
                .map_err(|error| format!("could not read {name} guard at RVA {rva:#x}: {error}"))?;
            if actual != expected {
                return Err(format!("{name} guard changed at RVA {rva:#x}"));
            }
        }
        Ok(())
    }

    /// Prove that the live VTL1 image is the build behind this manifest, then prove every guarded
    /// site. The callback reads by RVA from the already validated Secure Kernel image base.
    /// Nothing in this path mutates target state.
    pub(crate) fn verify_live_image<F, E>(&self, mut read: F) -> Result<LiveImageProof, String>
    where
        F: FnMut(u32, usize) -> Result<Vec<u8>, E>,
        E: Display,
    {
        self.validate()?;
        let header = read(0, 4096)
            .map_err(|error| format!("could not read the live Secure Kernel PE header: {error}"))?;
        let pe = parse_live_pe(&header)?;
        if pe.machine != self.image.pe.machine
            || pe.sections != self.image.pe.sections
            || pe.timestamp != self.image.pe.timestamp
            || pe.size_of_image != self.image.pe.size_of_image
            || pe.checksum != self.image.pe.checksum
        {
            return Err("live Secure Kernel PE identity does not match the M6 manifest".into());
        }

        let debug_size = usize::try_from(pe.debug_size)
            .map_err(|_| "live PE debug directory is too large".to_string())?;
        if pe.debug_rva == 0 || debug_size == 0 || !debug_size.is_multiple_of(28) {
            return Err("live Secure Kernel has no complete PE debug directory".into());
        }
        let debug = read(pe.debug_rva, debug_size).map_err(|error| {
            format!("could not read the live Secure Kernel debug directory: {error}")
        })?;
        if debug.len() != debug_size {
            return Err("live Secure Kernel debug-directory read was short".into());
        }
        let mut codeview = None;
        for entry in debug.as_chunks::<28>().0 {
            let kind = u32::from_le_bytes(entry[12..16].try_into().expect("four-byte slice"));
            let size = u32::from_le_bytes(entry[16..20].try_into().expect("four-byte slice"));
            let rva = u32::from_le_bytes(entry[20..24].try_into().expect("four-byte slice"));
            if kind == 2 && size >= 24 && rva != 0 && codeview.replace((rva, size)).is_some() {
                return Err("live Secure Kernel has more than one CodeView debug record".into());
            }
        }
        let (codeview_rva, codeview_size) = codeview
            .ok_or_else(|| "live Secure Kernel has no CodeView debug record".to_string())?;
        let codeview_size = usize::try_from(codeview_size)
            .map_err(|_| "live CodeView record is too large".to_string())?;
        let codeview = read(codeview_rva, codeview_size)
            .map_err(|error| format!("could not read the live CodeView record: {error}"))?;
        if codeview.len() != codeview_size || codeview.get(..4) != Some(b"RSDS") {
            return Err("live Secure Kernel CodeView record is short or not RSDS".into());
        }
        let guid = canonical_guid(
            codeview[4..20]
                .try_into()
                .expect("the RSDS length check covers its GUID"),
        );
        let age = u32::from_le_bytes(
            codeview[20..24]
                .try_into()
                .expect("the RSDS length check covers its age"),
        );
        if !guid.eq_ignore_ascii_case(&self.image.pdb.guid) || age != self.image.pdb.age {
            return Err("live Secure Kernel PDB identity does not match the M6 manifest".into());
        }

        self.verify_guards(read)?;
        Ok(LiveImageProof {
            machine: pe.machine,
            sections: pe.sections,
            timestamp: pe.timestamp,
            size_of_image: pe.size_of_image,
            checksum: pe.checksum,
            pdb_guid: guid,
            pdb_age: age,
        })
    }

    pub(crate) fn breakpoints(
        &self,
        image_base: u64,
    ) -> Result<Vec<crate::sklive::BreakpointGuard>, String> {
        self.validate()?;
        self.sites
            .iter()
            .map(|site| {
                let address = image_base
                    .checked_add(u64::from(site.rva))
                    .ok_or_else(|| format!("{} breakpoint address wraps", site.phase))?;
                let guard = decode_hex(&site.phase, &site.guard)?;
                let mut decoder = Decoder::with_ip(64, &guard, address, DecoderOptions::NONE);
                let instruction = decoder.decode();
                if instruction.is_invalid() || instruction.len() == 0 {
                    return Err(format!(
                        "{} site does not begin with a complete AMD64 instruction",
                        site.phase
                    ));
                }
                Ok(crate::sklive::BreakpointGuard {
                    slot: site.slot,
                    instruction: crate::sklive::InstructionGuard {
                        address: crate::skcontrol::HexU64(address),
                        bytes: guard[..instruction.len()].to_vec(),
                    },
                })
            })
            .collect()
    }

    fn site(&self, phase: &str) -> Result<&Site, String> {
        self.sites
            .iter()
            .find(|site| site.phase == phase)
            .ok_or_else(|| format!("manifest has no {phase} site"))
    }

    fn static_guard(&self, name: &str) -> Result<&StaticGuard, String> {
        self.static_guards
            .iter()
            .find(|guard| guard.name == name)
            .ok_or_else(|| format!("manifest has no {name} guard"))
    }
}

struct LivePe {
    machine: u16,
    sections: u16,
    timestamp: u32,
    size_of_image: u32,
    checksum: u32,
    debug_rva: u32,
    debug_size: u32,
}

fn parse_live_pe(header: &[u8]) -> Result<LivePe, String> {
    if header.len() < 0x40 || header.get(..2) != Some(b"MZ") {
        return Err("live Secure Kernel image has no DOS header".into());
    }
    let pe_offset = u32::from_le_bytes(
        header[0x3c..0x40]
            .try_into()
            .expect("the DOS-header length was checked"),
    ) as usize;
    let optional = pe_offset
        .checked_add(24)
        .ok_or_else(|| "live PE header offset wraps".to_string())?;
    const DEBUG_DIRECTORY_END: usize = 112 + 7 * 8;
    let required = optional
        .checked_add(DEBUG_DIRECTORY_END)
        .ok_or_else(|| "live PE optional-header size wraps".to_string())?;
    if required > header.len()
        || header.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0")
        || u16::from_le_bytes(
            header[optional..optional + 2]
                .try_into()
                .expect("the optional-header length was checked"),
        ) != 0x20b
    {
        return Err("live Secure Kernel image is not a complete PE32+ header".into());
    }
    let word = |at: usize| {
        u16::from_le_bytes(
            header[at..at + 2]
                .try_into()
                .expect("the PE-header length was checked"),
        )
    };
    let dword = |at: usize| {
        u32::from_le_bytes(
            header[at..at + 4]
                .try_into()
                .expect("the PE-header length was checked"),
        )
    };
    if usize::from(word(pe_offset + 20)) < DEBUG_DIRECTORY_END || dword(optional + 108) < 7 {
        return Err("live Secure Kernel PE32+ header does not declare the debug directory".into());
    }
    Ok(LivePe {
        machine: word(pe_offset + 4),
        sections: word(pe_offset + 6),
        timestamp: dword(pe_offset + 8),
        size_of_image: dword(optional + 56),
        checksum: dword(optional + 64),
        debug_rva: dword(optional + 112 + 6 * 8),
        debug_size: dword(optional + 112 + 6 * 8 + 4),
    })
}

fn canonical_guid(raw: [u8; 16]) -> String {
    let first = u32::from_le_bytes(raw[..4].try_into().expect("four-byte GUID field"));
    let second = u16::from_le_bytes(raw[4..6].try_into().expect("two-byte GUID field"));
    let third = u16::from_le_bytes(raw[6..8].try_into().expect("two-byte GUID field"));
    let tail = raw[8..]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!("{first:08X}{second:04X}{third:04X}{tail}")
}

fn validate_layout(layout: &Layout) -> Result<(), String> {
    if layout.size == 0
        || layout.alignment == 0
        || !layout.alignment.is_power_of_two()
        || !layout.size.is_multiple_of(layout.alignment)
    {
        return Err("request layout has an invalid size or alignment".into());
    }
    let mut names = HashSet::new();
    let mut occupied = vec![false; layout.size as usize];
    for field in &layout.fields {
        let end = field
            .offset
            .checked_add(field.width)
            .ok_or_else(|| format!("field {} wraps", field.name))?;
        if field.name.is_empty()
            || !names.insert(&field.name)
            || !matches!(field.width, 1 | 2 | 4 | 8)
            || field.alignment == 0
            || !field.alignment.is_power_of_two()
            || !field.offset.is_multiple_of(field.alignment)
            || end > layout.size
        {
            return Err(format!("invalid request field {}", field.name));
        }
        for byte in &mut occupied[field.offset as usize..end as usize] {
            if *byte {
                return Err(format!(
                    "request field {} overlaps another field",
                    field.name
                ));
            }
            *byte = true;
        }
    }
    Ok(())
}

fn guard_in_image(image: &ImageIdentity, name: &str, rva: u32, guard: &str) -> Result<(), String> {
    let bytes = decode_hex(name, guard)?;
    let length = u32::try_from(bytes.len()).map_err(|_| format!("{name} guard is too large"))?;
    let end = rva
        .checked_add(length)
        .ok_or_else(|| format!("{name} guard wraps its RVA"))?;
    if bytes.is_empty() || end > image.pe.size_of_image {
        return Err(format!("{name} guard is empty or outside the image"));
    }
    Ok(())
}

fn decode_hex(name: &str, encoded: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err(format!("{name} has an odd-length hex guard"));
    }
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or_else(|| format!("{name} is not hexadecimal"))?;
            let low = hex_digit(pair[1]).ok_or_else(|| format!("{name} is not hexadecimal"))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn observed<'a>(manifest: &'a ServiceManifest) -> ObservedImageIdentity<'a> {
        ObservedImageIdentity {
            module: &manifest.image.module,
            file_version: &manifest.image.file_version,
            file_size: manifest.image.file_size,
            sha256: &manifest.image.sha256,
            machine: manifest.image.pe.machine,
            sections: manifest.image.pe.sections,
            timestamp: manifest.image.pe.timestamp,
            size_of_image: manifest.image.pe.size_of_image,
            checksum: manifest.image.pe.checksum,
            pdb_guid: &manifest.image.pdb.guid,
            pdb_age: manifest.image.pdb.age,
        }
    }

    fn guards(manifest: &ServiceManifest) -> HashMap<u32, Vec<u8>> {
        manifest
            .sites
            .iter()
            .map(|site| (site.rva, decode_hex(&site.phase, &site.guard).unwrap()))
            .chain(
                manifest
                    .static_guards
                    .iter()
                    .map(|guard| (guard.rva, decode_hex(&guard.name, &guard.guard).unwrap())),
            )
            .collect()
    }

    fn rsds_guid(canonical: &str) -> [u8; 16] {
        let bytes = decode_hex("test guid", canonical).unwrap();
        let mut raw = [0_u8; 16];
        raw[..4].copy_from_slice(&bytes[..4].iter().rev().copied().collect::<Vec<_>>());
        raw[4..6].copy_from_slice(&bytes[4..6].iter().rev().copied().collect::<Vec<_>>());
        raw[6..8].copy_from_slice(&bytes[6..8].iter().rev().copied().collect::<Vec<_>>());
        raw[8..].copy_from_slice(&bytes[8..]);
        raw
    }

    fn mapped_image(manifest: &ServiceManifest) -> Vec<u8> {
        let mut image = vec![0_u8; manifest.image.pe.size_of_image as usize];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&manifest.image.pe.machine.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&manifest.image.pe.sections.to_le_bytes());
        image[0x88..0x8c].copy_from_slice(&manifest.image.pe.timestamp.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        let optional = 0x98;
        image[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&16_u32.to_le_bytes());
        image[optional + 56..optional + 60]
            .copy_from_slice(&manifest.image.pe.size_of_image.to_le_bytes());
        image[optional + 64..optional + 68]
            .copy_from_slice(&manifest.image.pe.checksum.to_le_bytes());
        let debug = optional + 112 + 6 * 8;
        image[debug..debug + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[debug + 4..debug + 8].copy_from_slice(&28_u32.to_le_bytes());
        image[0x1000 + 12..0x1000 + 16].copy_from_slice(&2_u32.to_le_bytes());
        image[0x1000 + 16..0x1000 + 20].copy_from_slice(&32_u32.to_le_bytes());
        image[0x1000 + 20..0x1000 + 24].copy_from_slice(&0x1100_u32.to_le_bytes());
        image[0x1100..0x1104].copy_from_slice(b"RSDS");
        image[0x1104..0x1114].copy_from_slice(&rsds_guid(&manifest.image.pdb.guid));
        image[0x1114..0x1118].copy_from_slice(&manifest.image.pdb.age.to_le_bytes());
        image[0x1118..0x1120].copy_from_slice(b"test.pdb");
        for (rva, bytes) in guards(manifest) {
            image[rva as usize..rva as usize + bytes.len()].copy_from_slice(&bytes);
        }
        image
    }

    #[test]
    fn the_embedded_manifest_is_self_consistent() {
        let manifest = service_manifest().expect("the qualified manifest is valid");
        manifest
            .verify_identity(&observed(&manifest))
            .expect("its identity agrees with itself");
        let bytes = guards(&manifest);
        manifest
            .verify_guards(|rva, _| bytes.get(&rva).cloned().ok_or("missing"))
            .expect("every complete guard is present");
    }

    #[test]
    fn one_changed_image_byte_is_refused() {
        let manifest = service_manifest().unwrap();
        let mut bytes = guards(&manifest);
        let dispatch = manifest.site("dispatch").unwrap();
        bytes.get_mut(&dispatch.rva).unwrap()[0] ^= 1;
        let error = manifest
            .verify_guards(|rva, _| bytes.get(&rva).cloned().ok_or("missing"))
            .unwrap_err();
        assert!(error.contains("dispatch guard changed"), "{error}");
    }

    #[test]
    fn one_changed_rva_is_refused() {
        let mut manifest = service_manifest().unwrap();
        manifest.sites[1].rva += 1;
        let error = manifest.validate().unwrap_err();
        assert!(
            error.contains("handler call") || error.contains("return site"),
            "{error}"
        );
    }

    #[test]
    fn one_changed_layout_offset_is_refused() {
        let mut manifest = service_manifest().unwrap();
        manifest
            .request_layout
            .fields
            .iter_mut()
            .find(|field| field.name == "service_number")
            .unwrap()
            .offset += 1;
        let error = manifest.validate().unwrap_err();
        assert!(
            error.contains("service source and request layout disagree"),
            "{error}"
        );
    }

    #[test]
    fn a_fifth_hardware_slot_is_refused() {
        let mut manifest = service_manifest().unwrap();
        manifest.hardware_slots_required = 5;
        let error = manifest.validate().unwrap_err();
        assert!(error.contains("one through four hardware slots"), "{error}");
    }

    #[test]
    fn a_neighbouring_image_identity_is_refused() {
        let manifest = service_manifest().unwrap();
        let mut observed = observed(&manifest);
        observed.timestamp ^= 1;
        let error = manifest.verify_identity(&observed).unwrap_err();
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn a_live_image_must_match_its_pe_pdb_and_every_guard_before_mutation() {
        let manifest = service_manifest().unwrap();
        let image = mapped_image(&manifest);
        let proof = manifest
            .verify_live_image(|rva, size| {
                image
                    .get(rva as usize..rva as usize + size)
                    .map(<[u8]>::to_vec)
                    .ok_or("outside fixture")
            })
            .unwrap();
        assert_eq!(proof.timestamp, manifest.image.pe.timestamp);
        assert_eq!(proof.pdb_guid, manifest.image.pdb.guid);

        let mut stale_pe = image.clone();
        stale_pe[0x88] ^= 1;
        let error = manifest
            .verify_live_image(|rva, size| {
                stale_pe
                    .get(rva as usize..rva as usize + size)
                    .map(<[u8]>::to_vec)
                    .ok_or("outside fixture")
            })
            .unwrap_err();
        assert!(error.contains("PE identity"), "{error}");

        let mut stale_pdb = image;
        stale_pdb[0x1104] ^= 1;
        let error = manifest
            .verify_live_image(|rva, size| {
                stale_pdb
                    .get(rva as usize..rva as usize + size)
                    .map(<[u8]>::to_vec)
                    .ok_or("outside fixture")
            })
            .unwrap_err();
        assert!(error.contains("PDB identity"), "{error}");
    }

    #[test]
    fn a_live_pe_must_declare_the_debug_directory_it_exposes() {
        let manifest = service_manifest().unwrap();
        let mut short_optional = mapped_image(&manifest);
        short_optional[0x94..0x96].copy_from_slice(&0xa0_u16.to_le_bytes());
        let error = manifest
            .verify_live_image(|rva, size| {
                short_optional
                    .get(rva as usize..rva as usize + size)
                    .map(<[u8]>::to_vec)
                    .ok_or("outside fixture")
            })
            .unwrap_err();
        assert!(
            error.contains("does not declare the debug directory"),
            "{error}"
        );

        let mut too_few_directories = mapped_image(&manifest);
        let count = 0x98 + 108;
        too_few_directories[count..count + 4].copy_from_slice(&6_u32.to_le_bytes());
        let error = manifest
            .verify_live_image(|rva, size| {
                too_few_directories
                    .get(rva as usize..rva as usize + size)
                    .map(<[u8]>::to_vec)
                    .ok_or("outside fixture")
            })
            .unwrap_err();
        assert!(
            error.contains("does not declare the debug directory"),
            "{error}"
        );
    }

    #[test]
    fn live_breakpoints_are_derived_only_from_manifest_sites() {
        let manifest = service_manifest().unwrap();
        let base = 0xffff_f807_0000_0000;
        let breakpoints = manifest.breakpoints(base).unwrap();
        assert_eq!(breakpoints.len(), manifest.hardware_slots_required as usize);
        for (breakpoint, site) in breakpoints.iter().zip(&manifest.sites) {
            assert_eq!(breakpoint.slot, site.slot);
            assert_eq!(breakpoint.instruction.address.0, base + u64::from(site.rva));
            let complete_guard = decode_hex(&site.phase, &site.guard).unwrap();
            assert!(complete_guard.starts_with(&breakpoint.instruction.bytes));
            breakpoint.validate().unwrap();
        }
        assert_eq!(
            breakpoints
                .iter()
                .map(|breakpoint| breakpoint.instruction.bytes.len())
                .collect::<Vec<_>>(),
            vec![2, 5, 5]
        );
    }
}
