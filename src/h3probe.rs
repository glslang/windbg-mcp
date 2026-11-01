//! Typed user-mode ABI for the operator-installed `h3probe` driver.
//!
//! The driver source is carried under `drivers/h3probe`; this module opens its device but never
//! installs, starts or stops it. Provider roles own one handle in one process and issue only the
//! bounded register and memory operations needed by the live Secure Kernel path.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use anyhow::{Context, Result, bail};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::skcontrol::RegisterName;

const DEVICE: &str = r"\\.\H3Probe";
const FILE_SHARE_NONE: u32 = 0;
const PAGE: usize = 0x1000;
const ABI_VERSION: u32 = 1;
const IOCTL_H3_RUN: u32 = ctl_code(0x800);
const IOCTL_H3_READ_GPA: u32 = ctl_code(0x801);
const IOCTL_H3_CALL: u32 = ctl_code(0x804);
const IOCTL_H3_VID_TRANSLATE: u32 = ctl_code(0x810);
const IOCTL_H3_MEM_READ: u32 = ctl_code(0x812);
const IOCTL_H3_MEM_WRITE: u32 = ctl_code(0x813);
const HV_CALL_GET_VP_REGISTERS: u64 = 0x50;
const HV_CALL_SET_VP_REGISTERS: u64 = 0x51;
const CALL_BUFFER: usize = 64;
const CALL_OUTPUT: usize = 80;
const RUN_OUTPUT: usize = 16 + 8 * 60;
const MEMORY_REQUEST: usize = 40;
const MEMORY_ANSWER: usize = 32;
const MEMORY_READ_OUTPUT: usize = MEMORY_ANSWER + PAGE;
const VID_TRANSLATE_OUTPUT: usize = 112;

const fn ctl_code(function: u32) -> u32 {
    (0x22 << 16) | (function << 2)
}

pub(crate) trait Ioctl {
    fn ioctl(&self, code: u32, input: &[u8], output_size: usize) -> Result<Vec<u8>>;
}

pub(crate) struct Device(File);

impl Device {
    pub(crate) fn open() -> Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_NONE)
            .open(DEVICE)
            .map(Self)
            .with_context(|| format!("opening operator-installed {DEVICE}"))
    }
}

impl Ioctl for Device {
    fn ioctl(&self, code: u32, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        let input_len =
            u32::try_from(input.len()).context("h3probe input is larger than a DWORD")?;
        let output_len =
            u32::try_from(output_size).context("h3probe output is larger than a DWORD")?;
        let mut output = vec![0xaau8; output_size];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                self.0.as_raw_handle(),
                code,
                if input.is_empty() {
                    std::ptr::null()
                } else {
                    input.as_ptr().cast()
                },
                input_len,
                if output.is_empty() {
                    std::ptr::null_mut()
                } else {
                    output.as_mut_ptr().cast()
                },
                output_len,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("DeviceIoControl {code:#x}"));
        }
        let returned = usize::try_from(returned).expect("a DWORD fits usize on Windows");
        if returned > output.len() {
            bail!(
                "h3probe reported {returned} bytes into a {}-byte output",
                output.len()
            );
        }
        output.truncate(returned);
        Ok(output)
    }
}

pub(crate) struct Probe<D = Device> {
    device: D,
}

impl Probe<Device> {
    pub(crate) fn open() -> Result<Self> {
        Ok(Self {
            device: Device::open()?,
        })
    }
}

#[cfg(test)]
impl<D> Probe<D> {
    pub(crate) fn from_ioctl(device: D) -> Self {
        Self { device }
    }
}

impl<D: Ioctl> Probe<D> {
    fn call(&self, control: u64, block: &[u8]) -> Result<(u16, u64, u64)> {
        if block.len() > CALL_BUFFER {
            bail!("hypercall block exceeds h3probe's {CALL_BUFFER}-byte bound");
        }
        let mut request = vec![0u8; 16 + CALL_BUFFER];
        put_u64(&mut request, 0, control);
        put_u32(&mut request, 8, block.len() as u32);
        request[16..16 + block.len()].copy_from_slice(block);
        let output = self.device.ioctl(IOCTL_H3_CALL, &request, CALL_OUTPUT)?;
        if output.len() != CALL_OUTPUT {
            bail!(
                "h3probe register call returned {} of {CALL_OUTPUT} bytes",
                output.len()
            );
        }
        let result = get_u64(&output, 0)?;
        Ok((result as u16, get_u64(&output, 16)?, get_u64(&output, 24)?))
    }

    pub(crate) fn read_register(
        &self,
        partition: u64,
        vp: u32,
        input_vtl: u8,
        register: RegisterName,
    ) -> Result<RegisterWord> {
        let mut block = vec![0u8; 20];
        put_u64(&mut block, 0, partition);
        put_u32(&mut block, 8, vp);
        block[12] = input_vtl;
        put_u32(&mut block, 16, register_number(register));
        let (status, low, high) = self.call(HV_CALL_GET_VP_REGISTERS | (1 << 32), &block)?;
        Ok(RegisterWord { status, low, high })
    }

    pub(crate) fn read_named(
        &self,
        partition: u64,
        vp: u32,
        register: RegisterName,
    ) -> Result<RegisterWord> {
        self.read_register(partition, vp, 0x11, register)
    }

    pub(crate) fn read_active_vtl(&self, partition: u64, vp: u32) -> Result<RegisterWord> {
        // VsmVpStatus reports the executing VTL only when UseTargetVtl is clear. Ordinary
        // snapshots explicitly select VTL1 instead, because its status is part of the baseline
        // restored and compared while another VTL may be executing.
        self.read_register(partition, vp, 0x00, RegisterName::VsmVpStatus)
    }

    pub(crate) fn write_register(
        &self,
        partition: u64,
        vp: u32,
        register: RegisterName,
        low: u64,
        high: u64,
    ) -> Result<()> {
        let mut block = vec![0u8; 48];
        put_u64(&mut block, 0, partition);
        put_u32(&mut block, 8, vp);
        block[12] = 0x11;
        put_u32(&mut block, 16, register_number(register));
        put_u64(&mut block, 32, low);
        put_u64(&mut block, 40, high);
        let (status, _, _) = self.call(HV_CALL_SET_VP_REGISTERS | (1 << 32), &block)?;
        if status != 0 {
            bail!("setting {register:?} failed with HV_STATUS {status:#06x}");
        }
        let observed = self.read_named(partition, vp, register)?;
        let observed = observed.value(register)?;
        if observed != (low, high) {
            bail!(
                "setting {register:?} read back {:#018x}/{:#018x}, expected {low:#018x}/{high:#018x}",
                observed.0,
                observed.1
            );
        }
        Ok(())
    }

    pub(crate) fn children(&self) -> Result<HashMap<u64, Option<u16>>> {
        let output = self.device.ioctl(IOCTL_H3_RUN, &[], RUN_OUTPUT)?;
        if output.len() != RUN_OUTPUT {
            bail!(
                "h3probe RUN returned {} of {RUN_OUTPUT} bytes",
                output.len()
            );
        }
        let count = usize::try_from(get_u32(&output, 8)?).expect("u32 fits usize");
        if count > 8 {
            bail!("h3probe RUN claims {count} children; the ABI has 8 slots");
        }
        let mut children = HashMap::new();
        for index in 0..count {
            let at = 16 + index * 60;
            let partition = get_u64(&output, at)?;
            let status = get_u32(&output, at + 48)?;
            let enabled = get_u64(&output, at + 52)? as u16;
            children.insert(partition, (status == 0).then_some(enabled));
        }
        Ok(children)
    }

    pub(crate) fn guard(&self, partition: u64, vp: u32, expected_cr3: u64) -> Result<()> {
        let children = self.children()?;
        if children.get(&partition) != Some(&Some(3)) {
            bail!("partition {partition:#x} is not the selected VTL0+VTL1 child: {children:?}");
        }
        let observed = self
            .read_named(partition, vp, RegisterName::Cr3)?
            .low(RegisterName::Cr3)?;
        if observed != expected_cr3 {
            bail!("CR3 mismatch: got {observed:#x}, expected {expected_cr3:#x}");
        }
        Ok(())
    }

    pub(crate) fn identity(&self, partition: u64, vp: u32) -> Result<Vtl1Identity> {
        let children = self.children()?;
        if children.get(&partition) != Some(&Some(3)) {
            bail!("partition {partition:#x} is not the selected VTL0+VTL1 child: {children:?}");
        }
        let cr3 = self
            .read_named(partition, vp, RegisterName::Cr3)?
            .low(RegisterName::Cr3)?;
        let rip = self
            .read_named(partition, vp, RegisterName::Rip)?
            .low(RegisterName::Rip)?;
        let idtr = self.read_register_number(partition, vp, 1, 0x0007_0000)?;
        let (idtr_low, idtr_base) = idtr.value_number("IDTR")?;
        let idtr_limit = (idtr_low >> 48) as u16;
        if idtr_base == 0 || idtr_limit < 15 {
            bail!("VTL1 IDTR is invalid: base={idtr_base:#x}, limit={idtr_limit:#x}");
        }
        Ok(Vtl1Identity {
            cr3,
            rip,
            idtr_base,
            idtr_limit,
        })
    }

    fn read_register_number(
        &self,
        partition: u64,
        vp: u32,
        vtl: u8,
        register: u32,
    ) -> Result<RegisterWord> {
        let mut block = vec![0u8; 20];
        put_u64(&mut block, 0, partition);
        put_u32(&mut block, 8, vp);
        block[12] = (vtl & 0xf) | 0x10;
        put_u32(&mut block, 16, register);
        let (status, low, high) = self.call(HV_CALL_GET_VP_REGISTERS | (1 << 32), &block)?;
        Ok(RegisterWord { status, low, high })
    }

    pub(crate) fn read_memory(
        &self,
        target: MemoryTarget,
        gpa: u64,
        length: usize,
    ) -> Result<(MemoryAnswer, Vec<u8>)> {
        let request = memory_request(target, gpa, length)?;
        let output = self
            .device
            .ioctl(IOCTL_H3_MEM_READ, &request, MEMORY_READ_OUTPUT)?;
        if output.len() != MEMORY_READ_OUTPUT {
            bail!(
                "h3probe memory read returned {} of {MEMORY_READ_OUTPUT} bytes",
                output.len()
            );
        }
        let answer = MemoryAnswer::parse(&output, length)?;
        let data = output[MEMORY_ANSWER..MEMORY_ANSWER + answer.length].to_vec();
        Ok((answer, data))
    }

    pub(crate) fn write_memory(
        &self,
        target: MemoryTarget,
        gpa: u64,
        data: &[u8],
    ) -> Result<MemoryAnswer> {
        let mut request = memory_request(target, gpa, data.len())?;
        request.extend_from_slice(data);
        let output = self
            .device
            .ioctl(IOCTL_H3_MEM_WRITE, &request, MEMORY_ANSWER)?;
        if output.len() != MEMORY_ANSWER {
            bail!(
                "h3probe memory write returned {} of {MEMORY_ANSWER} bytes",
                output.len()
            );
        }
        MemoryAnswer::parse(&output, data.len())
    }

    pub(crate) fn read_gpa_hypercall(
        &self,
        partition: u64,
        gpa: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        if length > 16 {
            bail!("a hypercall GPA read is at most 16 bytes");
        }
        let mut request = vec![0u8; 24];
        put_u64(&mut request, 0, partition);
        put_u64(&mut request, 8, gpa);
        put_u32(&mut request, 16, length as u32);
        let output = self.device.ioctl(IOCTL_H3_READ_GPA, &request, 32)?;
        if output.len() < 16 + length {
            bail!("h3probe hypercall read returned {} bytes", output.len());
        }
        let status = get_u32(&output, 0)?;
        if status != 0 {
            bail!("HV_STATUS {status:#06x}");
        }
        let access = get_u64(&output, 8)?;
        if access != 0 {
            let name = match access {
                1 => "Unmapped",
                2 => "ReadIntercept",
                3 => "WriteIntercept",
                4 => "Rom",
                _ => "unknown",
            };
            bail!("REFUSED {name}({access})");
        }
        Ok(output[16..16 + length].to_vec())
    }

    pub(crate) fn translate_gpa(&self, target: MemoryTarget, gpa: u64) -> Result<VidTranslation> {
        let mut request = vec![0u8; 24];
        put_u32(&mut request, 0, target.owner_pid);
        put_u64(&mut request, 8, target.partition_handle);
        put_u64(&mut request, 16, gpa);
        let output = self
            .device
            .ioctl(IOCTL_H3_VID_TRANSLATE, &request, VID_TRANSLATE_OUTPUT)?;
        if output.len() != VID_TRANSLATE_OUTPUT {
            bail!(
                "h3probe VID translate returned {} of {VID_TRANSLATE_OUTPUT} bytes",
                output.len()
            );
        }
        let version = get_u32(&output, 0)?;
        if version != 2 {
            bail!("h3probe VID translate answered version {version}, expected 2");
        }
        let user_status = get_u32(&output, 4)?;
        let build_status = get_u32(&output, 16)?;
        let lookup_status = get_u32(&output, 20)?;
        let attached = get_u32(&output, 24)? != 0;
        let owner_read = get_u32(&output, 28)? != 0;
        let owner_matched = get_u32(&output, 32)? != 0;
        let handle_status = get_u32(&output, 36)?;
        let gpn = get_u64(&output, 56)?;
        let translate_status = get_u32(&output, 64)?;
        let information = get_u64(&output, 72)?;
        let fields = [
            get_u64(&output, 80)?,
            get_u64(&output, 88)?,
            get_u64(&output, 96)?,
            get_u64(&output, 104)?,
        ];
        let identity_matched = build_status == 0
            && lookup_status == 0
            && attached
            && owner_read
            && owner_matched
            && handle_status == 0;
        let succeeded =
            identity_matched && user_status == 0 && translate_status == 0 && information == 32;
        let kind = if !succeeded {
            VidRangeKind::Unknown
        } else if fields[1] != 0 {
            VidRangeKind::MemoryBlock
        } else if fields[0] != 0 {
            VidRangeKind::Other
        } else {
            VidRangeKind::None
        };
        Ok(VidTranslation {
            gpn,
            identity_matched,
            user_status,
            translate_status,
            information,
            fields,
            kind,
        })
    }

    pub(crate) fn unknown_ioctl_is_rejected(&self) -> bool {
        self.device.ioctl(ctl_code(0x8ff), &[], 0).is_err()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VidRangeKind {
    MemoryBlock,
    Other,
    None,
    Unknown,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct VidTranslation {
    pub(crate) gpn: u64,
    pub(crate) identity_matched: bool,
    pub(crate) user_status: u32,
    pub(crate) translate_status: u32,
    pub(crate) information: u64,
    pub(crate) fields: [u64; 4],
    pub(crate) kind: VidRangeKind,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RegisterWord {
    pub(crate) status: u16,
    pub(crate) low: u64,
    pub(crate) high: u64,
}

impl RegisterWord {
    pub(crate) fn value(self, register: RegisterName) -> Result<(u64, u64)> {
        self.value_number(&format!("{register:?}"))
    }

    pub(crate) fn low(self, register: RegisterName) -> Result<u64> {
        Ok(self.value(register)?.0)
    }

    fn value_number(self, name: &str) -> Result<(u64, u64)> {
        if self.status != 0 {
            bail!("{name} read failed with HV_STATUS {:#06x}", self.status);
        }
        Ok((self.low, self.high))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Vtl1Identity {
    pub(crate) cr3: u64,
    #[allow(dead_code)]
    pub(crate) rip: u64,
    pub(crate) idtr_base: u64,
    pub(crate) idtr_limit: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MemoryTarget {
    pub(crate) owner_pid: u32,
    pub(crate) partition_handle: u64,
    pub(crate) partition_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MemoryResult {
    Ok,
    NotPresent,
    Refused,
    Error,
    Identity,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct MemoryAnswer {
    pub(crate) result: MemoryResult,
    pub(crate) stage: u32,
    pub(crate) status: u32,
    pub(crate) length: usize,
    pub(crate) gpn: u64,
}

impl MemoryAnswer {
    fn parse(raw: &[u8], asked: usize) -> Result<Self> {
        if raw.len() < MEMORY_ANSWER {
            bail!(
                "h3probe memory answer is {} of {MEMORY_ANSWER} bytes",
                raw.len()
            );
        }
        let version = get_u32(raw, 0)?;
        if version != ABI_VERSION {
            bail!(
                "h3probe memory answered ABI version {version}; this client speaks {ABI_VERSION}"
            );
        }
        let result = match get_u32(raw, 4)? {
            0 => MemoryResult::Ok,
            1 => MemoryResult::NotPresent,
            2 => MemoryResult::Refused,
            3 => MemoryResult::Error,
            4 => MemoryResult::Identity,
            value => bail!("h3probe memory answered unknown result {value}"),
        };
        let stage = get_u32(raw, 8)?;
        if stage > 13 {
            bail!("h3probe memory answered unknown stage {stage}");
        }
        let status = get_u32(raw, 12)?;
        let length = get_u32(raw, 16)? as usize;
        let answer = Self {
            result,
            stage,
            status,
            length,
            gpn: get_u64(raw, 24)?,
        };
        if result == MemoryResult::Ok && (length != asked || stage != 0 || status != 0) {
            bail!("h3probe memory answered ok with {length} of {asked} bytes at stage {stage}");
        }
        if result != MemoryResult::Ok && length != 0 {
            bail!("h3probe memory answered {result:?} with {length} bytes");
        }
        Ok(answer)
    }

    pub(crate) fn protocol_failure(self) -> String {
        match self.result {
            MemoryResult::NotPresent => "NOTPRESENT".into(),
            MemoryResult::Refused => format!("REFUSED {}", stage_name(self.stage)),
            _ => format!(
                "ERROR h3 memory: {:?} at {} (status {:#010x}) for page {:#x}",
                self.result,
                stage_name(self.stage),
                self.status,
                self.gpn << 12
            ),
        }
    }
}

fn memory_request(target: MemoryTarget, gpa: u64, length: usize) -> Result<Vec<u8>> {
    if target.owner_pid == 0 || target.partition_handle == 0 {
        bail!("h3 memory needs a nonzero vmwp PID and partition handle");
    }
    if length == 0 || length > PAGE - (gpa as usize & (PAGE - 1)) {
        bail!("one h3 memory request must remain within one non-empty 4 KiB page");
    }
    let mut request = vec![0u8; MEMORY_REQUEST];
    put_u32(&mut request, 0, ABI_VERSION);
    put_u32(&mut request, 4, target.owner_pid);
    put_u64(&mut request, 8, target.partition_handle);
    put_u64(&mut request, 16, target.partition_id);
    put_u64(&mut request, 24, gpa);
    put_u32(&mut request, 32, length as u32);
    Ok(request)
}

pub(crate) fn register_number(register: RegisterName) -> u32 {
    match register {
        RegisterName::Rax => 0x0002_0000,
        RegisterName::Rcx => 0x0002_0001,
        RegisterName::Rdx => 0x0002_0002,
        RegisterName::Rbx => 0x0002_0003,
        RegisterName::Rsp => 0x0002_0004,
        RegisterName::Rbp => 0x0002_0005,
        RegisterName::Rsi => 0x0002_0006,
        RegisterName::Rdi => 0x0002_0007,
        RegisterName::R8 => 0x0002_0008,
        RegisterName::R9 => 0x0002_0009,
        RegisterName::R10 => 0x0002_000a,
        RegisterName::R11 => 0x0002_000b,
        RegisterName::R12 => 0x0002_000c,
        RegisterName::R13 => 0x0002_000d,
        RegisterName::R14 => 0x0002_000e,
        RegisterName::R15 => 0x0002_000f,
        RegisterName::Rip => 0x0002_0010,
        RegisterName::Rflags => 0x0002_0011,
        RegisterName::Cr3 => 0x0004_0002,
        RegisterName::Dr0 => 0x0005_0000,
        RegisterName::Dr1 => 0x0005_0001,
        RegisterName::Dr2 => 0x0005_0002,
        RegisterName::Dr3 => 0x0005_0003,
        RegisterName::Dr6 => 0x0005_0004,
        RegisterName::Dr7 => 0x0005_0005,
        RegisterName::Es => 0x0006_0000,
        RegisterName::Cs => 0x0006_0001,
        RegisterName::Ss => 0x0006_0002,
        RegisterName::Ds => 0x0006_0003,
        RegisterName::Fs => 0x0006_0004,
        RegisterName::Gs => 0x0006_0005,
        RegisterName::VsmVpStatus => 0x000d_0003,
    }
}

pub(crate) struct GuestVirtual<'a, D = Device> {
    probe: &'a Probe<D>,
    target: MemoryTarget,
    cr3: u64,
    pages: HashMap<u64, Vec<u8>>,
}

impl<'a, D: Ioctl> GuestVirtual<'a, D> {
    pub(crate) fn new(probe: &'a Probe<D>, target: MemoryTarget, cr3: u64) -> Result<Self> {
        if cr3 == 0 || cr3 & 0xfff != 0 {
            bail!("VTL1 CR3 is not a nonzero aligned address: {cr3:#x}");
        }
        Ok(Self {
            probe,
            target,
            cr3: cr3 & 0x000f_ffff_ffff_f000,
            pages: HashMap::new(),
        })
    }

    fn page(&mut self, gpa: u64) -> Result<&[u8]> {
        let page = gpa & !0xfff;
        if !self.pages.contains_key(&page) {
            let (answer, data) = self.probe.read_memory(self.target, page, PAGE)?;
            if answer.result != MemoryResult::Ok {
                bail!("GPA {page:#x}: {}", answer.protocol_failure());
            }
            self.pages.insert(page, data);
        }
        Ok(self.pages.get(&page).expect("the page was inserted"))
    }

    fn qword(&mut self, gpa: u64) -> Result<u64> {
        let offset = gpa as usize & 0xfff;
        get_u64(self.page(gpa)?, offset)
    }

    fn translate(&mut self, va: u64) -> Result<u64> {
        let mut table = self.cr3;
        for (level, shift) in [(4, 39), (3, 30), (2, 21), (1, 12)] {
            let entry = self.qword(table + ((va >> shift) & 0x1ff) * 8)?;
            if entry & 1 == 0 {
                bail!("VA {va:#x}: level {level} entry is not present");
            }
            if level == 3 && entry & (1 << 7) != 0 {
                return Ok((entry & 0x000f_ffff_c000_0000) | (va & ((1 << 30) - 1)));
            }
            if level == 2 && entry & (1 << 7) != 0 {
                return Ok((entry & 0x000f_ffff_ffe0_0000) | (va & ((1 << 21) - 1)));
            }
            table = entry & 0x000f_ffff_ffff_f000;
        }
        Ok(table | (va & 0xfff))
    }

    pub(crate) fn read(&mut self, mut va: u64, mut size: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(size);
        while size > 0 {
            let gpa = self.translate(va)?;
            let take = size.min(PAGE - (va as usize & (PAGE - 1)));
            let offset = gpa as usize & (PAGE - 1);
            result.extend_from_slice(&self.page(gpa)?[offset..offset + take]);
            va += take as u64;
            size -= take;
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeIdentity {
    machine: u16,
    timestamp: u32,
    size_of_image: u32,
}

pub(crate) fn find_secure_kernel_base<D: Ioctl>(
    guest: &mut GuestVirtual<'_, D>,
    idtr_base: u64,
    idtr_limit: u16,
    image: Option<&Path>,
) -> Result<u64> {
    let expected = image.map(disk_pe_identity).transpose()?;
    let table = guest.read(idtr_base, (usize::from(idtr_limit) + 1).min(PAGE))?;
    let mut handlers = Vec::new();
    let (gates, _) = table.as_chunks::<16>();
    for gate in gates {
        let address = u64::from(u16::from_le_bytes([gate[0], gate[1]]))
            | (u64::from(u16::from_le_bytes([gate[6], gate[7]])) << 16)
            | (u64::from(u32::from_le_bytes([gate[8], gate[9], gate[10], gate[11]])) << 32);
        if address != 0 && matches!(address >> 47, 0 | 0x1ffff) {
            handlers.push(address);
        }
    }
    if handlers.is_empty() {
        bail!("the live VTL1 IDT contains no canonical handler address");
    }
    let found = find_matching_image_base(&handlers, expected, |candidate| {
        guest
            .read(candidate, PAGE)
            .ok()
            .and_then(|header| pe_identity(&header))
    });
    if let Some(candidate) = found {
        return Ok(candidate);
    }
    bail!("no matching PE contains a VTL1 IDT handler within 16 MiB");
}

fn find_matching_image_base(
    handlers: &[u64],
    expected: Option<PeIdentity>,
    mut identify: impl FnMut(u64) -> Option<PeIdentity>,
) -> Option<u64> {
    let mut identities = HashMap::new();
    for handler in handlers {
        let start = handler & !0xfff;
        for page in 0..=(16 * 1024 * 1024 / PAGE) {
            let Some(candidate) = start.checked_sub((page * PAGE) as u64) else {
                break;
            };
            let identity = *identities
                .entry(candidate)
                .or_insert_with(|| identify(candidate));
            let Some(identity) = identity else {
                continue;
            };
            let Some(end) = candidate.checked_add(u64::from(identity.size_of_image)) else {
                continue;
            };
            if !(candidate..end).contains(handler) {
                continue;
            }
            if expected.is_some_and(|expected| expected != identity) {
                continue;
            }
            return Some(candidate);
        }
    }
    None
}

fn disk_pe_identity(path: &Path) -> Result<PeIdentity> {
    let bytes = std::fs::read(path).with_context(|| format!("reading image {}", path.display()))?;
    pe_identity(&bytes[..bytes.len().min(PAGE)])
        .with_context(|| format!("{} is not a PE32+ AMD64 image", path.display()))
}

fn pe_identity(data: &[u8]) -> Option<PeIdentity> {
    if data.len() < PAGE || data.get(..2)? != b"MZ" {
        return None;
    }
    let pe = usize::try_from(get_u32(data, 0x3c).ok()?).ok()?;
    if pe > data.len().checked_sub(0x108)? || data.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes(data.get(pe + 4..pe + 6)?.try_into().ok()?);
    let timestamp = get_u32(data, pe + 8).ok()?;
    let magic = u16::from_le_bytes(data.get(pe + 24..pe + 26)?.try_into().ok()?);
    let size_of_image = get_u32(data, pe + 24 + 0x38).ok()?;
    (machine == 0x8664 && magic == 0x20b && size_of_image != 0).then_some(PeIdentity {
        machine,
        timestamp,
        size_of_image,
    })
}

fn stage_name(stage: u32) -> &'static str {
    [
        "none",
        "request",
        "build",
        "process",
        "handle",
        "owner",
        "partition",
        "scratch",
        "translate",
        "block",
        "read",
        "write",
        "verify",
        "recheck",
    ]
    .get(stage as usize)
    .copied()
    .unwrap_or("unknown")
}

fn get_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let value = bytes
        .get(at..at + 4)
        .with_context(|| format!("field at {at:#x} exceeds a {}-byte reply", bytes.len()))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("the slice is four bytes"),
    ))
}

fn get_u64(bytes: &[u8], at: usize) -> Result<u64> {
    let value = bytes
        .get(at..at + 8)
        .with_context(|| format!("field at {at:#x} exceeds a {}-byte reply", bytes.len()))?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("the slice is eight bytes"),
    ))
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    struct RecordingIoctl(RefCell<Vec<Vec<u8>>>);

    impl Ioctl for RecordingIoctl {
        fn ioctl(&self, code: u32, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
            assert_eq!(code, IOCTL_H3_CALL);
            assert_eq!(output_size, CALL_OUTPUT);
            self.0.borrow_mut().push(input.to_vec());
            Ok(vec![0; CALL_OUTPUT])
        }
    }

    #[test]
    fn memory_answer_refuses_unknown_and_inconsistent_values() {
        let mut answer = vec![0u8; MEMORY_ANSWER];
        put_u32(&mut answer, 0, ABI_VERSION);
        put_u32(&mut answer, 4, 0);
        put_u32(&mut answer, 16, 8);
        assert_eq!(
            MemoryAnswer::parse(&answer, 8).unwrap().result,
            MemoryResult::Ok
        );

        put_u32(&mut answer, 4, 9);
        assert!(MemoryAnswer::parse(&answer, 8).is_err());
        put_u32(&mut answer, 4, 2);
        assert!(MemoryAnswer::parse(&answer, 8).is_err());
    }

    #[test]
    fn a_cached_pe_is_reconsidered_for_each_idt_handler() {
        let base = 0x10_0000;
        let identity = PeIdentity {
            machine: 0x8664,
            timestamp: 0x1234_5678,
            size_of_image: 0x2000,
        };
        let reads = Cell::new(0);
        let found = find_matching_image_base(&[base + 0x3000, base + 0x1000], None, |candidate| {
            (candidate == base).then(|| {
                reads.set(reads.get() + 1);
                identity
            })
        });
        assert_eq!(found, Some(base));
        assert_eq!(reads.get(), 1, "the parsed identity should be cached");
    }

    #[test]
    fn memory_requests_pin_the_driver_layout() {
        let target = MemoryTarget {
            owner_pid: 4242,
            partition_handle: 0x2e0,
            partition_id: 0x85,
        };
        let request = memory_request(target, 0x1234, 8).unwrap();
        assert_eq!(request.len(), 40);
        assert_eq!(get_u32(&request, 0).unwrap(), 1);
        assert_eq!(get_u32(&request, 4).unwrap(), 4242);
        assert_eq!(get_u64(&request, 8).unwrap(), 0x2e0);
        assert_eq!(get_u64(&request, 16).unwrap(), 0x85);
        assert_eq!(get_u64(&request, 24).unwrap(), 0x1234);
        assert_eq!(get_u32(&request, 32).unwrap(), 8);
    }

    #[test]
    fn every_protocol_register_has_the_expected_tlfs_number() {
        assert_eq!(register_number(RegisterName::Rip), 0x0002_0010);
        assert_eq!(register_number(RegisterName::Cr3), 0x0004_0002);
        assert_eq!(register_number(RegisterName::Dr7), 0x0005_0005);
        assert_eq!(register_number(RegisterName::VsmVpStatus), 0x000d_0003);
    }

    #[test]
    fn active_vtl_and_vtl1_status_use_distinct_hypercall_inputs() {
        let probe = Probe::from_ioctl(RecordingIoctl(RefCell::new(Vec::new())));
        probe.read_active_vtl(0x85, 0).unwrap();
        probe
            .read_named(0x85, 0, RegisterName::VsmVpStatus)
            .unwrap();
        probe.read_named(0x85, 0, RegisterName::Rip).unwrap();
        let calls = probe.device.0.borrow();
        assert_eq!(calls[0][16 + 12], 0x00);
        assert_eq!(calls[1][16 + 12], 0x11);
        assert_eq!(calls[2][16 + 12], 0x11);
    }
}
