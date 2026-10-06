//! Typed subset of the 64-bit kernel-debugger request protocol.
//!
//! This module deliberately contains only messages observed from the supported WinDbg build or
//! needed to answer those messages.  The serial framing lives in [`crate::kdwire`]; keeping the
//! state-manipulate layouts here makes the eventual named-pipe and KDNET transports share one
//! target implementation.

use std::fmt;

pub(crate) const MANIPULATE_BYTES: usize = 0x38;
pub(crate) const WAIT_STATE_CHANGE64_BYTES: usize = 0xf0;
pub(crate) const AMD64_CONTEXT_BYTES: usize = 0x4d0;
/// Protocol-only identity used where native KD expects an NT `KTHREAD` pointer.
///
/// The Secure Kernel does not have a compatible thread object. The target supplies a zero-filled
/// compatibility page at this otherwise unused canonical address; it is never mapped into or
/// written to the guest.
pub(crate) const SYNTHETIC_THREAD: u64 = 0xffff_fffe_fffe_0000;

pub(crate) const DBGKD_GET_VERSION_API: u32 = 0x3146;
pub(crate) const DBGKD_READ_VIRTUAL_MEMORY_API: u32 = 0x3130;
pub(crate) const DBGKD_READ_CONTROL_SPACE_API: u32 = 0x3137;
pub(crate) const DBGKD_WRITE_CONTROL_SPACE_API: u32 = 0x3138;
pub(crate) const DBGKD_RESTORE_BREAKPOINT_API: u32 = 0x3135;
pub(crate) const DBGKD_GET_CONTEXT_EX_API: u32 = 0x315f;
pub(crate) const DBGKD_SET_CONTEXT_API: u32 = 0x3133;
pub(crate) const DBGKD_WRITE_BREAKPOINT_API: u32 = 0x3134;
pub(crate) const DBGKD_CONTINUE_API2: u32 = 0x313c;

const STATUS_SUCCESS: u32 = 0;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const DBGKD_64BIT_PROTOCOL_VERSION2: u8 = 6;
const DBGKD_VERS_FLAG_PTR64: u16 = 0x0004;
const DBGKD_VERS_FLAG_NOMM: u16 = 0x0008;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManipulateRequest {
    bytes: [u8; MANIPULATE_BYTES],
    data: Vec<u8>,
}

impl ManipulateRequest {
    pub(crate) fn decode(payload: &[u8]) -> Result<Self, ApiError> {
        let bytes = payload
            .get(..MANIPULATE_BYTES)
            .ok_or(ApiError::ShortManipulate {
                actual: payload.len(),
            })?
            .try_into()
            .expect("slice length checked above");
        Ok(Self {
            bytes,
            data: payload[MANIPULATE_BYTES..].to_vec(),
        })
    }

    pub(crate) fn api_number(&self) -> u32 {
        word(&self.bytes, 0)
    }

    #[cfg(test)]
    fn processor_level(&self) -> u16 {
        half(&self.bytes, 4)
    }

    #[cfg(test)]
    fn processor(&self) -> u16 {
        half(&self.bytes, 6)
    }

    pub(crate) fn get_version_response(&self, version: Version64) -> Vec<u8> {
        let mut response = self.bytes;
        response[8..12].copy_from_slice(&STATUS_SUCCESS.to_le_bytes());
        response[12..16].fill(0);
        version.encode(&mut response[16..]);
        response.to_vec()
    }

    pub(crate) fn success_response(&self) -> Vec<u8> {
        self.status_response(STATUS_SUCCESS)
    }

    pub(crate) fn failure_response(&self) -> Vec<u8> {
        self.status_response(0xc000_0001)
    }

    fn status_response(&self, status: u32) -> Vec<u8> {
        let mut response = self.bytes;
        response[8..12].copy_from_slice(&status.to_le_bytes());
        response[12..16].fill(0);
        response.to_vec()
    }

    pub(crate) fn write_breakpoint_address(&self) -> Option<u64> {
        (self.api_number() == DBGKD_WRITE_BREAKPOINT_API).then(|| quad(&self.bytes, 16))
    }

    pub(crate) fn write_breakpoint_response(&self, handle: u32) -> Result<Vec<u8>, ApiError> {
        if self.write_breakpoint_address().is_none() {
            return Err(ApiError::WrongApi {
                expected: DBGKD_WRITE_BREAKPOINT_API,
                actual: self.api_number(),
            });
        }
        let mut response = self.success_response();
        response[24..28].copy_from_slice(&handle.to_le_bytes());
        Ok(response)
    }

    pub(crate) fn continue2_trace(&self) -> Option<bool> {
        (self.api_number() == DBGKD_CONTINUE_API2).then(|| word(&self.bytes, 20) != 0)
    }

    pub(crate) fn restore_breakpoint_handle(&self) -> Option<u32> {
        (self.api_number() == DBGKD_RESTORE_BREAKPOINT_API).then(|| word(&self.bytes, 16))
    }

    pub(crate) fn get_context_ex(&self) -> Option<ContextEx> {
        (self.api_number() == DBGKD_GET_CONTEXT_EX_API).then(|| ContextEx {
            offset: word(&self.bytes, 16),
            count: word(&self.bytes, 20),
        })
    }

    pub(crate) fn set_context(&self) -> Option<&[u8]> {
        (self.api_number() == DBGKD_SET_CONTEXT_API).then_some(self.data.as_slice())
    }

    pub(crate) fn get_context_ex_response(
        &self,
        context: &Amd64Context,
    ) -> Result<Vec<u8>, ApiError> {
        let request = self.get_context_ex().ok_or(ApiError::WrongApi {
            expected: DBGKD_GET_CONTEXT_EX_API,
            actual: self.api_number(),
        })?;
        let start = request.offset as usize;
        let end = start
            .checked_add(request.count as usize)
            .filter(|end| *end <= AMD64_CONTEXT_BYTES)
            .ok_or(ApiError::ContextRange {
                offset: request.offset,
                count: request.count,
            })?;
        if MANIPULATE_BYTES + request.count as usize > crate::kdwire::MAX_PACKET_BYTES {
            return Err(ApiError::ContextResponseTooLong {
                count: request.count,
            });
        }
        let mut response = self.success_response();
        response[24..28].copy_from_slice(&request.count.to_le_bytes());
        response.extend_from_slice(&context.bytes[start..end]);
        Ok(response)
    }

    pub(crate) fn read_virtual_memory(&self) -> Option<ReadMemory> {
        self.read_memory(DBGKD_READ_VIRTUAL_MEMORY_API)
    }

    pub(crate) fn read_control_space(&self) -> Option<ReadMemory> {
        self.read_memory(DBGKD_READ_CONTROL_SPACE_API)
    }

    pub(crate) fn write_control_space(&self) -> Option<(ReadMemory, &[u8])> {
        self.read_memory(DBGKD_WRITE_CONTROL_SPACE_API)
            .map(|request| (request, self.data.as_slice()))
    }

    fn read_memory(&self, api: u32) -> Option<ReadMemory> {
        (self.api_number() == api).then(|| ReadMemory {
            address: quad(&self.bytes, 16),
            count: word(&self.bytes, 24),
        })
    }

    pub(crate) fn read_virtual_memory_response(&self, bytes: &[u8]) -> Result<Vec<u8>, ApiError> {
        self.read_memory_response(DBGKD_READ_VIRTUAL_MEMORY_API, bytes)
    }

    pub(crate) fn read_control_space_response(&self, bytes: &[u8]) -> Result<Vec<u8>, ApiError> {
        self.read_memory_response(DBGKD_READ_CONTROL_SPACE_API, bytes)
    }

    fn read_memory_response(&self, api: u32, bytes: &[u8]) -> Result<Vec<u8>, ApiError> {
        let request = self.read_memory(api).ok_or(ApiError::WrongApi {
            expected: api,
            actual: self.api_number(),
        })?;
        self.finish_read_response(request, bytes)
    }

    fn finish_read_response(&self, request: ReadMemory, bytes: &[u8]) -> Result<Vec<u8>, ApiError> {
        if bytes.len() > request.count as usize {
            return Err(ApiError::ReadResponseTooLong {
                requested: request.count,
                actual: bytes.len(),
            });
        }
        let mut response = self.bytes.to_vec();
        response[8..12].copy_from_slice(&STATUS_SUCCESS.to_le_bytes());
        response[12..16].fill(0);
        response[28..32].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        response.extend_from_slice(bytes);
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadMemory {
    pub(crate) address: u64,
    pub(crate) count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ContextEx {
    pub(crate) offset: u32,
    pub(crate) count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Amd64Context {
    bytes: [u8; AMD64_CONTEXT_BYTES],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Amd64ContextValues {
    /// RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, then R8 through R15.
    pub(crate) gpr: [u64; 16],
    pub(crate) rip: u64,
    pub(crate) rflags: u32,
    /// CS, DS, ES, FS, GS and SS selectors.
    pub(crate) segments: [u16; 6],
    /// DR0, DR1, DR2, DR3, DR6 and DR7.
    pub(crate) debug: [u64; 6],
}

impl Amd64Context {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ApiError> {
        Ok(Self {
            bytes: bytes.try_into().map_err(|_| ApiError::BadContextSize {
                actual: bytes.len(),
            })?,
        })
    }

    pub(crate) fn from_values(values: &Amd64ContextValues) -> Self {
        let mut context = Self {
            bytes: [0; AMD64_CONTEXT_BYTES],
        };
        context.set_u32(0x30, 0x0010_001f);
        context.set_u32(0x34, 0x1f80);
        for (offset, value) in [0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42]
            .into_iter()
            .zip(values.segments)
        {
            context.set_u16(offset, value);
        }
        context.set_u32(0x44, values.rflags);
        for (offset, value) in [0x48, 0x50, 0x58, 0x60, 0x68, 0x70]
            .into_iter()
            .zip(values.debug)
        {
            context.set_u64(offset, value);
        }
        for (offset, value) in (0x78..=0xf0).step_by(8).zip(values.gpr) {
            context.set_u64(offset, value);
        }
        context.set_u64(0xf8, values.rip);
        context
    }

    pub(crate) fn from_wait_state(wait: &[u8]) -> Result<Self, ApiError> {
        if wait.len() != WAIT_STATE_CHANGE64_BYTES {
            return Err(ApiError::BadWaitStateSize { actual: wait.len() });
        }
        Ok(Self::from_values(&Amd64ContextValues {
            rip: quad(wait, 0x18),
            rflags: word(wait, 0xd0),
            segments: [
                half(wait, 0xe8),
                half(wait, 0xea),
                half(wait, 0xec),
                half(wait, 0xee),
                0,
                0x18,
            ],
            debug: [0, 0, 0, 0, quad(wait, 0xc0), quad(wait, 0xc8)],
            ..Amd64ContextValues::default()
        }))
    }

    pub(crate) fn matches_prefix(&self, bytes: &[u8]) -> bool {
        !bytes.is_empty() && self.bytes.starts_with(bytes)
    }

    fn set_u16(&mut self, at: usize, value: u16) {
        self.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn set_u32(&mut self, at: usize, value: u32) {
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn set_u64(&mut self, at: usize, value: u64) {
        self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
}

pub(crate) fn breakpoint_state_change(
    context: &Amd64ContextValues,
    instruction: &[u8],
) -> Result<Vec<u8>, ApiError> {
    if instruction.is_empty() || instruction.len() > 16 {
        return Err(ApiError::InstructionLength {
            actual: instruction.len(),
        });
    }
    let mut state = vec![0; WAIT_STATE_CHANGE64_BYTES];
    put_u32(&mut state, 0, 0x3030);
    put_u16(&mut state, 4, 0x000f);
    put_u16(&mut state, 6, 0);
    put_u32(&mut state, 8, 1);
    // WinDbg dereferences this field while preparing `t`. A null value is rejected, and pointing
    // it at real Secure Kernel code makes instruction bytes look like an NT KTHREAD pointer. The
    // target serves a bounded zero-filled compatibility page at this protocol-only address.
    put_u64(&mut state, 0x10, SYNTHETIC_THREAD);
    put_u64(&mut state, 0x18, context.rip);
    // Both hardware execute breakpoints and trap-flag steps arrive as vector 1. Reporting the
    // matching status prevents WinDbg from applying the one-byte RIP adjustment used for `int 3`.
    put_u32(&mut state, 0x20, 0x8000_0004);
    put_u64(&mut state, 0x30, context.rip);
    put_u32(&mut state, 0xb8, 1);
    put_u64(&mut state, 0xc0, context.debug[4]);
    put_u64(&mut state, 0xc8, context.debug[5]);
    put_u32(&mut state, 0xd0, context.rflags);
    put_u16(&mut state, 0xd4, instruction.len() as u16);
    put_u16(&mut state, 0xd6, 3);
    state[0xd8..0xd8 + instruction.len()].copy_from_slice(instruction);
    put_u16(&mut state, 0xe8, context.segments[0]);
    put_u16(&mut state, 0xea, context.segments[1]);
    put_u16(&mut state, 0xec, context.segments[2]);
    put_u16(&mut state, 0xee, context.segments[3]);
    Ok(state)
}

/// Values advertised by the small compatibility target.
///
/// `NOMM` is essential here: this target reads the Secure Kernel's virtual address space directly
/// and intentionally exposes no Windows physical-memory or page-table model to the debugger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Version64 {
    pub(crate) build: u16,
    pub(crate) kernel_base: u64,
}

impl Version64 {
    pub(crate) fn fixture(kernel_base: u64) -> Self {
        Self {
            build: 26_100,
            kernel_base,
        }
    }

    fn encode(self, out: &mut [u8]) {
        debug_assert!(out.len() >= 0x28);
        out[..0x28].fill(0);
        out[0..2].copy_from_slice(&0x000fu16.to_le_bytes());
        out[2..4].copy_from_slice(&self.build.to_le_bytes());
        out[4] = DBGKD_64BIT_PROTOCOL_VERSION2;
        out[6..8].copy_from_slice(&(DBGKD_VERS_FLAG_PTR64 | DBGKD_VERS_FLAG_NOMM).to_le_bytes());
        out[8..10].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        // These are one past the highest packet, state-change and manipulate values understood by
        // current 64-bit KD.  Unsupported manipulate requests still receive an explicit status.
        out[10] = 12;
        out[11] = 3;
        out[12] = 0x36;
        out[16..24].copy_from_slice(&self.kernel_base.to_le_bytes());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApiError {
    ShortManipulate { actual: usize },
    BadWaitStateSize { actual: usize },
    BadContextSize { actual: usize },
    WrongApi { expected: u32, actual: u32 },
    ReadResponseTooLong { requested: u32, actual: usize },
    ContextRange { offset: u32, count: u32 },
    ContextResponseTooLong { count: u32 },
    InstructionLength { actual: usize },
}

impl fmt::Display for ApiError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortManipulate { actual } => write!(
                out,
                "KD manipulate packet is {actual} bytes; expected at least {MANIPULATE_BYTES}"
            ),
            Self::BadWaitStateSize { actual } => write!(
                out,
                "KD wait-state change is {actual} bytes; expected {WAIT_STATE_CHANGE64_BYTES}"
            ),
            Self::BadContextSize { actual } => write!(
                out,
                "AMD64 context is {actual} bytes; expected {AMD64_CONTEXT_BYTES}"
            ),
            Self::WrongApi { expected, actual } => {
                write!(out, "KD API {actual:#x} is not expected API {expected:#x}")
            }
            Self::ReadResponseTooLong { requested, actual } => write!(
                out,
                "KD read response has {actual} bytes for a request of {requested} bytes"
            ),
            Self::ContextRange { offset, count } => write!(
                out,
                "KD context range {offset:#x}+{count:#x} exceeds {AMD64_CONTEXT_BYTES:#x} bytes"
            ),
            Self::ContextResponseTooLong { count } => write!(
                out,
                "KD context response of {count:#x} bytes exceeds one protocol packet"
            ),
            Self::InstructionLength { actual } => write!(
                out,
                "KD instruction report has {actual} bytes; expected 1..=16"
            ),
        }
    }
}

impl std::error::Error for ApiError {}

fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("bounded KD API field"))
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded KD API field"))
}

fn quad(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded KD API field"))
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_get_version_request_captured_from_windbg() {
        let captured = [
            0x46, 0x31, 0, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let request = ManipulateRequest::decode(&captured).unwrap();
        assert_eq!(request.api_number(), DBGKD_GET_VERSION_API);
        assert_eq!(request.processor_level(), 0);
        assert_eq!(request.processor(), 0);
    }

    #[test]
    fn get_version_response_has_the_public_amd64_layout() {
        let request = ManipulateRequest::decode(&[0; MANIPULATE_BYTES]).unwrap();
        let response = request.get_version_response(Version64::fixture(0xffff_f803_9e60_0000));
        assert_eq!(response.len(), MANIPULATE_BYTES);
        assert_eq!(word(&response, 8), STATUS_SUCCESS);
        assert_eq!(half(&response, 16), 0x000f);
        assert_eq!(half(&response, 18), 26_100);
        assert_eq!(response[20], DBGKD_64BIT_PROTOCOL_VERSION2);
        assert_eq!(half(&response, 24), IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(
            u64::from_le_bytes(response[32..40].try_into().unwrap()),
            0xffff_f803_9e60_0000
        );
    }

    #[test]
    fn rejects_a_short_manipulate_header() {
        assert_eq!(
            ManipulateRequest::decode(&[0; MANIPULATE_BYTES - 1]),
            Err(ApiError::ShortManipulate {
                actual: MANIPULATE_BYTES - 1
            })
        );
    }

    #[test]
    fn decodes_and_answers_the_first_virtual_read_captured_from_windbg() {
        let captured = [
            0x30, 0x31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x02, 0, 0, 0x80, 0xf7,
            0xff, 0xff, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let request = ManipulateRequest::decode(&captured).unwrap();
        assert_eq!(
            request.read_virtual_memory(),
            Some(ReadMemory {
                address: 0xffff_f780_0000_0268,
                count: 1
            })
        );
        let response = request.read_virtual_memory_response(&[0]).unwrap();
        assert_eq!(word(&response, 8), STATUS_SUCCESS);
        assert_eq!(word(&response, 28), 1);
        assert_eq!(response.len(), MANIPULATE_BYTES + 1);
        assert_eq!(response[MANIPULATE_BYTES], 0);
    }

    #[test]
    fn protocol_sizes_match_the_measured_amd64_abi() {
        assert_eq!(MANIPULATE_BYTES, 0x38);
        assert_eq!(WAIT_STATE_CHANGE64_BYTES, 0xf0);
    }

    #[test]
    fn decodes_the_restore_breakpoint_request_captured_from_windbg() {
        let mut captured = [0; MANIPULATE_BYTES];
        captured[..4].copy_from_slice(&DBGKD_RESTORE_BREAKPOINT_API.to_le_bytes());
        captured[8..12].copy_from_slice(&0x103u32.to_le_bytes());
        captured[16..20].copy_from_slice(&1u32.to_le_bytes());
        let request = ManipulateRequest::decode(&captured).unwrap();
        assert_eq!(request.restore_breakpoint_handle(), Some(1));
        assert_eq!(word(&request.success_response(), 8), STATUS_SUCCESS);
    }

    #[test]
    fn answers_the_context_ex_request_captured_from_windbg() {
        let mut wait = [0; WAIT_STATE_CHANGE64_BYTES];
        wait[0x18..0x20].copy_from_slice(&0xffff_f803_9e63_32cfu64.to_le_bytes());
        wait[0xc8..0xd0].copy_from_slice(&0x400u64.to_le_bytes());
        wait[0xd0..0xd4].copy_from_slice(&0x202u32.to_le_bytes());
        wait[0xe8..0xea].copy_from_slice(&0x10u16.to_le_bytes());
        let context = Amd64Context::from_wait_state(&wait).unwrap();

        let mut captured = [0; MANIPULATE_BYTES];
        captured[..4].copy_from_slice(&DBGKD_GET_CONTEXT_EX_API.to_le_bytes());
        captured[16..20].copy_from_slice(&0u32.to_le_bytes());
        captured[20..24].copy_from_slice(&0x3d0u32.to_le_bytes());
        let request = ManipulateRequest::decode(&captured).unwrap();
        assert_eq!(
            request.get_context_ex(),
            Some(ContextEx {
                offset: 0,
                count: 0x3d0
            })
        );
        let response = request.get_context_ex_response(&context).unwrap();
        assert_eq!(response.len(), MANIPULATE_BYTES + 0x3d0);
        assert_eq!(word(&response, 24), 0x3d0);
        assert_eq!(word(&response, MANIPULATE_BYTES + 0x44), 0x202);
        assert_eq!(
            quad(&response, MANIPULATE_BYTES + 0xf8),
            0xffff_f803_9e63_32cf
        );
    }

    #[test]
    fn an_empty_context_write_is_not_an_unchanged_prefix() {
        let context = Amd64Context::from_values(&Amd64ContextValues::default());
        assert!(!context.matches_prefix(&[]));
        assert!(context.matches_prefix(&context.bytes[..1]));
    }

    #[test]
    fn builds_an_amd64_breakpoint_state_change() {
        let values = Amd64ContextValues {
            rip: 0xffff_f803_9e63_32cf,
            rflags: 0x202,
            segments: [0x10, 0x18, 0x18, 0x30, 0, 0x18],
            debug: [0, 0, 0, 0, 0x4000, 0x400],
            ..Amd64ContextValues::default()
        };
        let state = breakpoint_state_change(&values, &[0xcc]).unwrap();
        assert_eq!(state.len(), WAIT_STATE_CHANGE64_BYTES);
        assert_eq!(word(&state, 0), 0x3030);
        assert_eq!(quad(&state, 0x10), SYNTHETIC_THREAD);
        assert_eq!(quad(&state, 0x18), values.rip);
        assert_eq!(word(&state, 0x20), 0x8000_0004);
        assert_eq!(quad(&state, 0x30), values.rip);
        assert_eq!(word(&state, 0xb8), 1);
        assert_eq!(half(&state, 0xd4), 1);
        assert_eq!(state[0xd8], 0xcc);
    }
}
