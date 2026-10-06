//! Bounded codec and sequencing for the serial KD packet stream.
//!
//! KDNET carries these packets after its own handshake and encryption.  Keeping this layer
//! transport-neutral lets the named-pipe gate settle the debugger protocol before the network
//! envelope is attempted.

use std::fmt;

pub(crate) const INITIAL_PACKET_ID: u32 = 0x8080_0000;
pub(crate) const MAX_PACKET_BYTES: usize = 4_000;

const HEADER_BYTES: usize = 16;
const PACKET_LEADER: u32 = 0x3030_3030;
const CONTROL_PACKET_LEADER: u32 = 0x6969_6969;
const PACKET_TRAILING_BYTE: u8 = 0xaa;
const BREAK_IN_BYTE: u8 = 0x62;

pub(crate) const PACKET_TYPE_STATE_MANIPULATE: u16 = 2;
pub(crate) const PACKET_TYPE_ACKNOWLEDGE: u16 = 4;
pub(crate) const PACKET_TYPE_RESEND: u16 = 5;
pub(crate) const PACKET_TYPE_RESET: u16 = 6;
pub(crate) const PACKET_TYPE_STATE_CHANGE64: u16 = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DataPacket {
    pub(crate) packet_type: u16,
    pub(crate) id: u32,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    BreakIn,
    Control { packet_type: u16, id: u32 },
    Data(DataPacket),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    Oversized { byte_count: usize },
    ControlPayload { byte_count: usize, checksum: u32 },
    BadChecksum { expected: u32, actual: u32 },
    MissingTrailer { actual: u8 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversized { byte_count } => write!(
                out,
                "KD packet declares {byte_count} bytes; the protocol maximum is {MAX_PACKET_BYTES}"
            ),
            Self::ControlPayload {
                byte_count,
                checksum,
            } => write!(
                out,
                "KD control packet has byte count {byte_count} and checksum {checksum:#x}"
            ),
            Self::BadChecksum { expected, actual } => write!(
                out,
                "KD packet checksum is {actual:#x}, expected {expected:#x}"
            ),
            Self::MissingTrailer { actual } => {
                write!(out, "KD packet trailer is {actual:#x}, expected 0xaa")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Default)]
pub(crate) struct Decoder {
    buffered: Vec<u8>,
}

impl Decoder {
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buffered.extend_from_slice(bytes);
    }

    pub(crate) fn next(&mut self) -> Result<Option<Frame>, DecodeError> {
        self.discard_noise();
        let Some(first) = self.buffered.first().copied() else {
            return Ok(None);
        };
        if first == BREAK_IN_BYTE {
            self.buffered.remove(0);
            return Ok(Some(Frame::BreakIn));
        }
        if self.buffered.len() < HEADER_BYTES {
            return Ok(None);
        }

        let leader = word(&self.buffered, 0);
        let packet_type = half(&self.buffered, 4);
        let byte_count = usize::from(half(&self.buffered, 6));
        let id = word(&self.buffered, 8);
        let checksum = word(&self.buffered, 12);
        if byte_count > MAX_PACKET_BYTES {
            self.buffered.remove(0);
            return Err(DecodeError::Oversized { byte_count });
        }

        if leader == CONTROL_PACKET_LEADER {
            self.buffered.drain(..HEADER_BYTES);
            if byte_count != 0 || checksum != 0 {
                return Err(DecodeError::ControlPayload {
                    byte_count,
                    checksum,
                });
            }
            return Ok(Some(Frame::Control { packet_type, id }));
        }

        let total = HEADER_BYTES + byte_count + 1;
        if self.buffered.len() < total {
            return Ok(None);
        }
        let trailer = self.buffered[total - 1];
        if trailer != PACKET_TRAILING_BYTE {
            self.buffered.remove(0);
            return Err(DecodeError::MissingTrailer { actual: trailer });
        }
        let payload = self.buffered[HEADER_BYTES..HEADER_BYTES + byte_count].to_vec();
        let actual = checksum_bytes(&payload);
        self.buffered.drain(..total);
        if actual != checksum {
            return Err(DecodeError::BadChecksum {
                expected: checksum,
                actual,
            });
        }
        Ok(Some(Frame::Data(DataPacket {
            packet_type,
            id,
            payload,
        })))
    }

    fn discard_noise(&mut self) {
        let first_frame = self
            .buffered
            .iter()
            .position(|byte| matches!(*byte, BREAK_IN_BYTE | 0x30 | 0x69));
        match first_frame {
            Some(0) => {}
            Some(at) => {
                self.buffered.drain(..at);
            }
            None => self.buffered.clear(),
        }

        while self
            .buffered
            .first()
            .is_some_and(|byte| *byte != BREAK_IN_BYTE)
        {
            let byte = self.buffered[0];
            let needed = if byte == 0x30 {
                PACKET_LEADER.to_le_bytes()
            } else {
                CONTROL_PACKET_LEADER.to_le_bytes()
            };
            let compare = self.buffered.len().min(needed.len());
            if self.buffered[..compare] == needed[..compare] {
                break;
            }
            self.buffered.remove(0);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Inbound {
    pub(crate) writes: Vec<Vec<u8>>,
    pub(crate) packet: Option<DataPacket>,
    pub(crate) break_in: bool,
    pub(crate) peer_reset: bool,
}

impl Inbound {
    fn quiet() -> Self {
        Self {
            writes: Vec::new(),
            packet: None,
            break_in: false,
            peer_reset: false,
        }
    }
}

pub(crate) struct TargetLink {
    send_id: u32,
    receive_id: u32,
    outstanding: Option<Vec<u8>>,
}

impl TargetLink {
    pub(crate) fn new() -> Self {
        Self {
            send_id: INITIAL_PACKET_ID,
            receive_id: INITIAL_PACKET_ID,
            outstanding: None,
        }
    }

    pub(crate) fn receive(&mut self, frame: Frame) -> Inbound {
        let mut inbound = Inbound::quiet();
        match frame {
            Frame::BreakIn => inbound.break_in = true,
            Frame::Control {
                packet_type: PACKET_TYPE_RESET,
                ..
            } => {
                self.send_id = INITIAL_PACKET_ID;
                self.receive_id = INITIAL_PACKET_ID;
                self.outstanding = None;
                inbound.writes.push(control(PACKET_TYPE_RESET, 0));
                inbound.peer_reset = true;
            }
            Frame::Control {
                packet_type: PACKET_TYPE_ACKNOWLEDGE,
                id,
            } if id == self.send_id => {
                self.send_id ^= 1;
                self.outstanding = None;
            }
            Frame::Control {
                packet_type: PACKET_TYPE_RESEND,
                ..
            } => match self.outstanding.clone() {
                Some(packet) => inbound.writes.push(packet),
                None => inbound.writes.push(control(PACKET_TYPE_RESET, 0)),
            },
            Frame::Control { .. } => {}
            Frame::Data(packet) if packet.id == self.receive_id => {
                inbound
                    .writes
                    .push(control(PACKET_TYPE_ACKNOWLEDGE, packet.id));
                self.receive_id ^= 1;
                inbound.packet = Some(packet);
            }
            Frame::Data(packet) if packet.id == (self.receive_id ^ 1) => {
                inbound
                    .writes
                    .push(control(PACKET_TYPE_ACKNOWLEDGE, packet.id));
            }
            Frame::Data(_) => inbound.writes.push(control(PACKET_TYPE_RESEND, 0)),
        }
        inbound
    }

    pub(crate) fn send(&mut self, packet_type: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
        if self.outstanding.is_some() {
            return Err("a KD data packet is still awaiting acknowledgement".to_string());
        }
        let packet = data(packet_type, self.send_id, payload)?;
        self.outstanding = Some(packet.clone());
        Ok(packet)
    }

    pub(crate) fn awaiting_acknowledgement(&self) -> bool {
        self.outstanding.is_some()
    }
}

pub(crate) fn control(packet_type: u16, id: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    bytes.extend_from_slice(&CONTROL_PACKET_LEADER.to_le_bytes());
    bytes.extend_from_slice(&packet_type.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

pub(crate) fn data(packet_type: u16, id: u32, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > MAX_PACKET_BYTES {
        return Err(format!(
            "KD packet payload is {} bytes; maximum is {MAX_PACKET_BYTES}",
            payload.len()
        ));
    }
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len() + 1);
    bytes.extend_from_slice(&PACKET_LEADER.to_le_bytes());
    bytes.extend_from_slice(&packet_type.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&checksum_bytes(payload).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.push(PACKET_TRAILING_BYTE);
    Ok(bytes)
}

fn checksum_bytes(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}

fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("bounded KD header"))
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded KD header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_windbg_reset_capture_decodes() {
        let captured = [
            0x69, 0x69, 0x69, 0x69, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mut decoder = Decoder::default();
        for chunk in captured.chunks(3) {
            decoder.push(chunk);
        }
        assert_eq!(
            decoder.next().unwrap(),
            Some(Frame::Control {
                packet_type: PACKET_TYPE_RESET,
                id: 0,
            })
        );
        assert_eq!(decoder.next().unwrap(), None);
    }

    #[test]
    fn data_round_trips_across_every_boundary() {
        let encoded = data(PACKET_TYPE_STATE_MANIPULATE, INITIAL_PACKET_ID, &[1, 2, 3]).unwrap();
        for split in 0..=encoded.len() {
            let mut decoder = Decoder::default();
            decoder.push(&encoded[..split]);
            let first = decoder.next().unwrap();
            decoder.push(&encoded[split..]);
            let second = decoder.next().unwrap();
            let decoded = first.or(second).unwrap();
            assert_eq!(
                decoded,
                Frame::Data(DataPacket {
                    packet_type: PACKET_TYPE_STATE_MANIPULATE,
                    id: INITIAL_PACKET_ID,
                    payload: vec![1, 2, 3],
                })
            );
        }
    }

    #[test]
    fn decoder_resynchronizes_after_noise_and_bad_trailer() {
        let mut bad = data(PACKET_TYPE_STATE_MANIPULATE, INITIAL_PACKET_ID, &[4]).unwrap();
        *bad.last_mut().unwrap() = 0;
        let good = control(PACKET_TYPE_RESET, 0);
        let mut decoder = Decoder::default();
        decoder.push(&[0xff, 0x12, 0x30, 0x69]);
        decoder.push(&bad);
        decoder.push(&good);
        assert!(matches!(
            decoder.next(),
            Err(DecodeError::MissingTrailer { actual: 0 })
        ));
        assert_eq!(
            decoder.next().unwrap(),
            Some(Frame::Control {
                packet_type: PACKET_TYPE_RESET,
                id: 0,
            })
        );
    }

    #[test]
    fn decoder_rejects_bad_checksum_and_oversize() {
        let mut corrupt = data(PACKET_TYPE_STATE_MANIPULATE, INITIAL_PACKET_ID, &[4]).unwrap();
        corrupt[12] ^= 1;
        let mut decoder = Decoder::default();
        decoder.push(&corrupt);
        assert!(matches!(
            decoder.next(),
            Err(DecodeError::BadChecksum { .. })
        ));

        let mut oversized = control(PACKET_TYPE_RESET, 0);
        oversized[..4].copy_from_slice(&PACKET_LEADER.to_le_bytes());
        oversized[6..8].copy_from_slice(&((MAX_PACKET_BYTES + 1) as u16).to_le_bytes());
        decoder.push(&oversized);
        assert_eq!(
            decoder.next(),
            Err(DecodeError::Oversized {
                byte_count: MAX_PACKET_BYTES + 1,
            })
        );
    }

    #[test]
    fn link_resets_acknowledges_and_suppresses_duplicates() {
        let mut link = TargetLink::new();
        let reset = link.receive(Frame::Control {
            packet_type: PACKET_TYPE_RESET,
            id: 0,
        });
        assert!(reset.peer_reset);
        assert_eq!(reset.writes, vec![control(PACKET_TYPE_RESET, 0)]);

        let packet = DataPacket {
            packet_type: PACKET_TYPE_STATE_MANIPULATE,
            id: INITIAL_PACKET_ID,
            payload: vec![9],
        };
        let accepted = link.receive(Frame::Data(packet.clone()));
        assert_eq!(accepted.packet, Some(packet.clone()));
        assert_eq!(
            accepted.writes,
            vec![control(PACKET_TYPE_ACKNOWLEDGE, INITIAL_PACKET_ID)]
        );
        let duplicate = link.receive(Frame::Data(packet));
        assert_eq!(duplicate.packet, None);
        assert_eq!(
            duplicate.writes,
            vec![control(PACKET_TYPE_ACKNOWLEDGE, INITIAL_PACKET_ID)]
        );
    }

    #[test]
    fn link_retransmits_only_the_outstanding_packet() {
        let mut link = TargetLink::new();
        let sent = link
            .send(PACKET_TYPE_STATE_CHANGE64, &[0x30, 0x30])
            .unwrap();
        assert!(
            link.send(PACKET_TYPE_STATE_CHANGE64, &[0x31])
                .unwrap_err()
                .contains("awaiting acknowledgement")
        );
        let resend = link.receive(Frame::Control {
            packet_type: PACKET_TYPE_RESEND,
            id: 0,
        });
        assert_eq!(resend.writes, vec![sent]);
        let ack = link.receive(Frame::Control {
            packet_type: PACKET_TYPE_ACKNOWLEDGE,
            id: INITIAL_PACKET_ID,
        });
        assert!(ack.writes.is_empty());
        link.send(PACKET_TYPE_STATE_CHANGE64, &[0x31]).unwrap();
    }
}
