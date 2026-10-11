//! Bounded reads of a mapped PE's version resource before advertising a KD build.
//!
//! Resource offsets are relative to the resource directory, except for a data entry's RVA.
//! See https://learn.microsoft.com/windows/win32/debug/pe-format#the-rsrc-section.

use anyhow::{Context, Result, ensure};

const MAX_RESOURCE_BYTES: u32 = 0x1_0000;
const MAX_DIRECTORY_ENTRIES: usize = 256;
const PAGE: u32 = 0x1000;

pub(crate) fn validate_build(
    base: u64,
    expected: u16,
    mut read: impl FnMut(u64, u32) -> Result<Vec<u8>>,
) -> Result<u16> {
    ensure!(
        base >> 48 == 0xffff && base & 0xfff == 0,
        "invalid Secure Kernel image base"
    );
    let mut read_exact = |rva: u32, count: u32| -> Result<Vec<u8>> {
        let address = base
            .checked_add(u64::from(rva))
            .context("image address overflow")?;
        address
            .checked_add(u64::from(count))
            .context("image read overflow")?;
        let bytes = read(address, count)?;
        ensure!(
            bytes.len() == count as usize,
            "short Secure Kernel image read"
        );
        Ok(bytes)
    };
    let header = read_exact(0, PAGE)?;
    let identity =
        crate::sk::pe_identity(&header).context("Secure Kernel base is not a PE64 image")?;
    ensure!(
        identity.machine == 0x8664 && identity.size_of_image >= PAGE,
        "Secure Kernel image is not AMD64"
    );
    let nt = word(&header, 0x3c)? as usize;
    let optional = nt.checked_add(24).context("PE header offset overflow")?;
    ensure!(
        half(&header, nt + 20)? >= 136 && word(&header, optional + 108)? >= 3,
        "Secure Kernel image has no resource directory"
    );
    let rva = word(&header, optional + 128)?;
    let size = word(&header, optional + 132)?;
    ensure!(
        rva != 0 && (16..=MAX_RESOURCE_BYTES).contains(&size),
        "Secure Kernel resource directory is absent or too large"
    );
    ensure!(
        rva.checked_add(size)
            .is_some_and(|end| end <= identity.size_of_image),
        "Secure Kernel resource directory lies outside the image"
    );
    let mut resources = Vec::with_capacity(size as usize);
    while resources.len() < size as usize {
        let offset = resources.len() as u32;
        resources.extend(read_exact(rva + offset, (size - offset).min(PAGE))?);
    }
    // A PE resource tree has exactly three directory levels: type, name, language. Requiring
    // those shapes also bounds cycles and prevents interpreting directory bytes as version data.
    let version = directory_entry(&resources, 0, Some(16), true)?;
    let name = directory_entry(&resources, version, None, true)?;
    let leaf = directory_entry(&resources, name, None, false)?;
    let data_rva = word(&resources, leaf)?;
    let data_size = word(&resources, leaf + 4)?;
    let offset = data_rva
        .checked_sub(rva)
        .context("version data precedes resource directory")?;
    ensure!(data_size >= 92, "truncated Secure Kernel version resource");
    let end = offset
        .checked_add(data_size)
        .context("version resource size overflow")?;
    let data = resources
        .get(offset as usize..end as usize)
        .context("version data lies outside resource directory")?;
    let build = version_build(data)?;
    ensure!(
        build == expected,
        "live Secure Kernel image build {build} does not match profiled build {expected}"
    );
    tracing::info!(
        kernel_base = format_args!("{base:#x}"),
        timestamp = identity.timestamp,
        size_of_image = identity.size_of_image,
        build,
        "validated KD base and build against the live Secure Kernel PE version resource"
    );
    Ok(build)
}

fn directory_entry(bytes: &[u8], at: usize, id: Option<u32>, directory: bool) -> Result<usize> {
    let entries = usize::from(half(bytes, at + 12)?) + usize::from(half(bytes, at + 14)?);
    ensure!(
        (1..=MAX_DIRECTORY_ENTRIES).contains(&entries),
        "invalid PE resource entry count"
    );
    let start = at
        .checked_add(16)
        .context("resource directory offset overflow")?;
    let table = bytes
        .get(start..start + entries * 8)
        .context("truncated PE resource directory")?;
    let entry = table
        .as_chunks::<8>()
        .0
        .iter()
        .find(|entry| id.is_none_or(|id| word(*entry, 0).ok() == Some(id)))
        .context("PE image has no version resource")?;
    let target = word(entry, 4)?;
    ensure!(
        (target & 0x8000_0000 != 0) == directory,
        "unexpected PE resource tree depth"
    );
    let offset = (target & 0x7fff_ffff) as usize;
    ensure!(
        offset < bytes.len(),
        "PE resource offset lies outside directory"
    );
    Ok(offset)
}

fn version_build(bytes: &[u8]) -> Result<u16> {
    let length = usize::from(half(bytes, 0)?);
    ensure!(
        length <= bytes.len() && length >= 92 && half(bytes, 2)? == 52 && half(bytes, 4)? == 0,
        "invalid VS_VERSIONINFO length or type"
    );
    let key: Vec<u8> = "VS_VERSION_INFO\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    ensure!(
        bytes.get(6..6 + key.len()) == Some(key.as_slice()),
        "invalid VS_VERSIONINFO key"
    );
    // DWORD-aligned VS_FIXEDFILEINFO follows the UTF-16 key, at offset 40.
    ensure!(
        word(bytes, 40)? == 0xfeef_04bd && word(bytes, 44)? == 0x0001_0000,
        "invalid VS_FIXEDFILEINFO signature or version"
    );
    ensure!(
        word(bytes, 48)? == 0x000a_0000,
        "Secure Kernel file version is not Windows 10"
    );
    Ok((word(bytes, 52)? >> 16) as u16)
}

fn half(bytes: &[u8], at: usize) -> Result<u16> {
    let end = at.checked_add(2).context("PE field offset overflow")?;
    let field = bytes.get(at..end).context("truncated PE field")?;
    Ok(u16::from_le_bytes(field.try_into()?))
}

fn word(bytes: &[u8], at: usize) -> Result<u32> {
    let end = at.checked_add(4).context("PE field offset overflow")?;
    let field = bytes.get(at..end).context("truncated PE field")?;
    Ok(u32::from_le_bytes(field.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0xffff_f800_0000_0000;

    fn put(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn image() -> Vec<u8> {
        let mut bytes = vec![0; 0x2000];
        bytes[..2].copy_from_slice(b"MZ");
        put(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        put(&mut bytes, 0x84, 0x8664);
        put(&mut bytes, 0x94, 0xf0);
        put(&mut bytes, 0x98, 0x20b);
        put(&mut bytes, 0x98 + 56, 0x2000);
        put(&mut bytes, 0x98 + 108, 16);
        put(&mut bytes, 0x98 + 128, 0x1000);
        put(&mut bytes, 0x98 + 132, 0x200);
        for (at, id, target) in [
            (0x1000, 16, 0x8000_0020),
            (0x1020, 1, 0x8000_0040),
            (0x1040, 0x409, 0x60),
        ] {
            put(&mut bytes, at + 12, 1 << 16);
            put(&mut bytes, at + 16, id);
            put(&mut bytes, at + 20, target);
        }
        put(&mut bytes, 0x1060, 0x1080);
        put(&mut bytes, 0x1064, 92);
        put(&mut bytes, 0x1080, 92 | (52 << 16));
        for (index, byte) in "VS_VERSION_INFO\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .enumerate()
        {
            bytes[0x1086 + index] = byte;
        }
        put(&mut bytes, 0x1080 + 40, 0xfeef_04bd);
        put(&mut bytes, 0x1080 + 44, 0x0001_0000);
        put(&mut bytes, 0x1080 + 48, 0x000a_0000);
        put(&mut bytes, 0x1080 + 52, (26_100 << 16) | 9457);
        bytes
    }

    fn validate(bytes: &[u8], expected: u16) -> Result<u16> {
        validate_build(BASE, expected, |address, count| {
            ensure!(count <= PAGE);
            let offset = usize::try_from(address - BASE)?;
            Ok(bytes
                .get(offset..offset + count as usize)
                .context("unmapped fixture page")?
                .to_vec())
        })
    }

    #[test]
    fn build_is_read_from_the_mapped_image_and_must_match_the_profile() {
        let bytes = image();
        assert_eq!(validate(&bytes, 26_100).unwrap(), 26_100);
        assert!(
            validate(&bytes, 29_648)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    #[test]
    fn refuses_missing_malformed_and_out_of_bounds_image_metadata() {
        for (at, value) in [
            (0, 0),
            (0x84, 0xaa64),
            (0x98, 0x10b),
            (0x94, 0x70),
            (0x98 + 108, 2),
            (0x98 + 128, 0),
            (0x98 + 132, MAX_RESOURCE_BYTES + 1),
            (0x1014, 0xffff_ffff),
            (0x1034, 0x8000_0020),
            (0x1054, 0x8000_0060),
            (0x100c, 0xffff_ffff),
            (0x1060, 0xffff_ffff),
            (0x1064, 91),
            (0x1080, 91 | (52 << 16)),
            (0x1080 + 40, 0),
            (0x1080 + 48, 0),
        ] {
            let mut bytes = image();
            put(&mut bytes, at, value);
            assert!(
                validate(&bytes, 26_100).is_err(),
                "accepted malformed field at {at:#x}"
            );
        }
        assert!(validate_build(BASE, 26_100, |_, _| Ok(vec![])).is_err());
        assert!(validate_build(!0xfffu64, 26_100, |_, count| Ok(vec![0; count as usize])).is_err());
    }
}
