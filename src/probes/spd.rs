//! Read-only SPD EEPROM decode for JEDEC, XMP, and EXPO data rates.
//!
//! Profiles live on the DIMM, not in SMBIOS. Linux exposes them only when an SPD
//! driver (`ee1004`, `spd5118`, …) has bound and `/sys/bus/i2c/devices/*/eeprom`
//! is readable. This probe never loads I2C modules and never writes the EEPROM.

use std::path::Path;

use crate::model::Status;
use crate::probes::firmware;
use crate::probes::{finding_detail, Context, Findings};

const SRC: &str = "linux-sysfs";
pub(crate) const FEATURES: &[&str] = &["memory_xmp"];

const DDR3: u8 = 0x0b;
const DDR4: u8 = 0x0c;
const DDR5: u8 = 0x12;
const XMP_MAGIC: [u8; 2] = [0x0c, 0x4a];
const EXPO_MAGIC: &[u8] = b"EXPO";
const DDR4_XMP_OFF: usize = 0x180;
const DDR5_VENDOR_OFF: usize = 0x280;
const XMP3_HEADER_LEN: usize = 0x40;
const XMP3_PROFILE_LEN: usize = 0x40;
const EXPO_HEADER_LEN: usize = 0x0a;

pub(crate) fn findings(ctx: &Context) -> Findings {
    vec![memory_xmp(ctx)]
}

fn memory_xmp(ctx: &Context) -> (&'static str, crate::model::Detection) {
    let mut complete = true;
    let dumps = match read_spd_eeproms(ctx, &mut complete) {
        Ok(dumps) => dumps,
        Err(reason) => {
            return finding_detail(SRC, "memory_xmp", Status::Unknown, reason);
        }
    };
    if dumps.is_empty() {
        return finding_detail(
            SRC,
            "memory_xmp",
            Status::Unknown,
            if complete {
                "no SPD EEPROM sysfs nodes (ee1004/spd5118 not bound)"
            } else {
                "SPD EEPROM enumeration incomplete"
            },
        );
    }

    let decoded: Vec<_> = dumps
        .iter()
        .filter_map(|(id, bytes)| decode_spd(bytes).map(|info| (id.as_str(), info)))
        .collect();
    if decoded.is_empty() {
        return finding_detail(
            SRC,
            "memory_xmp",
            Status::Unknown,
            "SPD EEPROM present but not a recognised DDR3/4/5 dump",
        );
    }

    let operating = firmware::dimm_speeds(ctx)
        .into_iter()
        .filter_map(|dimm| dimm.operating_mts())
        .collect::<Vec<_>>();
    let mut parts = Vec::new();
    let mut any_profile = false;
    let mut any_match = false;
    let mut truncated = false;

    for (id, info) in &decoded {
        if info.truncated {
            truncated = true;
        }
        let mut stick = Vec::new();
        if let Some(jedec) = info.jedec_mts {
            stick.push(format!("JEDEC {jedec}"));
        }
        for profile in &info.profiles {
            any_profile = true;
            stick.push(profile.to_string());
            if operating
                .iter()
                .any(|rate| matches_rate(*rate, profile.mts))
            {
                any_match = true;
            }
        }
        if info.header && info.profiles.is_empty() {
            any_profile = true;
            stick.push("overclock profile header present, speed not decoded".into());
        }
        if stick.is_empty() {
            stick.push("no JEDEC or profile data rate".into());
        }
        parts.push(format!("{id}: {}", stick.join(", ")));
    }

    if !operating.is_empty() {
        let min = *operating.iter().min().unwrap();
        let max = *operating.iter().max().unwrap();
        let rate = if min == max {
            format!("{max} MT/s")
        } else {
            format!("{min}-{max} MT/s")
        };
        if any_match {
            parts.push(format!(
                "firmware operating {rate} (matches XMP/EXPO, not JEDEC-only)"
            ));
        } else if any_profile {
            parts.push(format!(
                "firmware operating {rate} (profiles present, not clearly applied)"
            ));
        } else {
            parts.push(format!("firmware operating {rate}"));
        }
    }

    if truncated {
        parts.push("some SPD dumps lack the XMP/EXPO region (need 512+ bytes)".into());
    }

    let status = if any_match {
        Status::Enabled
    } else if any_profile {
        Status::Present
    } else if decoded.iter().any(|(_, info)| info.truncated) {
        Status::Unknown
    } else {
        Status::Absent
    };
    let detail = if parts.is_empty() {
        "no profile or data-rate fields decoded".into()
    } else {
        parts.join("; ")
    };
    finding_detail(SRC, "memory_xmp", status, detail)
}

struct SpdInfo {
    jedec_mts: Option<u32>,
    profiles: Vec<Profile>,
    truncated: bool,
    header: bool,
}

struct Profile {
    kind: &'static str,
    index: u8,
    name: Option<String>,
    mts: u32,
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{}{} {name} {} MT/s", self.kind, self.index, self.mts),
            None => write!(f, "{}{} {} MT/s", self.kind, self.index, self.mts),
        }
    }
}

fn read_spd_eeproms(ctx: &Context, complete: &mut bool) -> Result<Vec<(String, Vec<u8>)>, String> {
    let root = Path::new("/sys/bus/i2c/devices");
    let entries = match ctx.reader.read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("I2C device sysfs not present".into());
        }
        Err(error) => {
            return Err(format!("cannot inspect I2C devices: {error}"));
        }
    };
    let mut dumps = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            *complete = false;
            continue;
        };
        if entry.file_name.starts_with("i2c-") {
            continue;
        }
        match ctx.reader.read(&entry.path.join("eeprom")) {
            Ok(bytes) if is_spd(&bytes) => dumps.push((entry.file_name, bytes)),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => *complete = false,
        }
    }
    Ok(dumps)
}

fn is_spd(bytes: &[u8]) -> bool {
    bytes.len() >= 128 && matches!(bytes[2], DDR3 | DDR4 | DDR5)
}

fn decode_spd(bytes: &[u8]) -> Option<SpdInfo> {
    if !is_spd(bytes) {
        return None;
    }
    Some(match bytes[2] {
        DDR5 => decode_ddr5(bytes),
        DDR4 => decode_ddr4(bytes),
        _ => decode_ddr3(bytes),
    })
}

fn decode_ddr5(bytes: &[u8]) -> SpdInfo {
    let jedec_mts = u16_le(bytes, 20).and_then(ddr5_mts);
    let truncated = bytes.len() < DDR5_VENDOR_OFF + XMP3_HEADER_LEN;
    let mut profiles = Vec::new();
    if bytes.len() >= DDR5_VENDOR_OFF + 4 {
        let region = &bytes[DDR5_VENDOR_OFF..];
        if region.starts_with(&XMP_MAGIC) {
            profiles.extend(parse_xmp3(region));
            let hybrid = XMP3_HEADER_LEN + 2 * XMP3_PROFILE_LEN;
            if region.len() >= hybrid + 4 && region[hybrid..].starts_with(EXPO_MAGIC) {
                profiles.extend(parse_expo(&region[hybrid..]));
            }
        } else if region.starts_with(EXPO_MAGIC) {
            profiles.extend(parse_expo(region));
        } else if let Some(at) = find_subslice(region, EXPO_MAGIC) {
            profiles.extend(parse_expo(&region[at..]));
        }
    }
    let header = bytes.len() >= DDR5_VENDOR_OFF + 4
        && (bytes[DDR5_VENDOR_OFF..].starts_with(&XMP_MAGIC)
            || bytes[DDR5_VENDOR_OFF..].starts_with(EXPO_MAGIC)
            || !profiles.is_empty());
    SpdInfo {
        jedec_mts,
        profiles,
        truncated,
        header,
    }
}

fn decode_ddr4(bytes: &[u8]) -> SpdInfo {
    let jedec_mts = ddr4_jedec_mts(bytes);
    let truncated = bytes.len() < DDR4_XMP_OFF + 2;
    let header = bytes.len() >= DDR4_XMP_OFF + 2 && bytes[DDR4_XMP_OFF..].starts_with(&XMP_MAGIC);
    let profiles = if bytes.len() >= DDR4_XMP_OFF + 48 && header {
        parse_xmp2(&bytes[DDR4_XMP_OFF..])
    } else {
        Vec::new()
    };
    SpdInfo {
        jedec_mts,
        profiles,
        truncated,
        header,
    }
}

fn decode_ddr3(bytes: &[u8]) -> SpdInfo {
    let header = bytes.len() >= 178 && bytes[176..].starts_with(&XMP_MAGIC);
    SpdInfo {
        jedec_mts: None,
        profiles: Vec::new(),
        truncated: bytes.len() < 256,
        header,
    }
}

fn parse_xmp3(region: &[u8]) -> Vec<Profile> {
    if region.len() < XMP3_HEADER_LEN {
        return Vec::new();
    }
    let enable = region[3];
    let mut profiles = Vec::new();
    let hybrid_expo = region.len() >= XMP3_HEADER_LEN + 2 * XMP3_PROFILE_LEN + 4
        && region[XMP3_HEADER_LEN + 2 * XMP3_PROFILE_LEN..].starts_with(EXPO_MAGIC);
    let count = if hybrid_expo { 2 } else { 3 };
    for i in 0..count {
        let start = XMP3_HEADER_LEN + i * XMP3_PROFILE_LEN;
        let Some(tck) = u16_le(region, start + 5) else {
            continue;
        };
        let Some(mts) = ddr5_mts(tck) else {
            continue;
        };
        if enable & (1 << i) == 0 && tck == 0 {
            continue;
        }
        if enable & (1 << i) == 0 && !plausible_mts(mts) {
            continue;
        }
        let name_off = 0x0e + i * 16;
        profiles.push(Profile {
            kind: "XMP",
            index: (i as u8) + 1,
            name: ascii_name(region.get(name_off..name_off + 16).unwrap_or(&[])),
            mts,
        });
    }
    profiles
}

fn parse_expo(region: &[u8]) -> Vec<Profile> {
    if region.len() < EXPO_HEADER_LEN + 6 {
        return Vec::new();
    }
    let enable = region[5];
    let mut profiles = Vec::new();
    for i in 0..2 {
        let start = EXPO_HEADER_LEN + i * 0x28;
        let Some(tck) = u16_le(region, start + 4) else {
            continue;
        };
        let Some(mts) = ddr5_mts(tck) else {
            continue;
        };
        let bit = if i == 0 { 0 } else { 4 };
        if enable & (1 << bit) == 0 && (tck == 0 || !plausible_mts(mts)) {
            continue;
        }
        profiles.push(Profile {
            kind: "EXPO",
            index: (i as u8) + 1,
            name: None,
            mts,
        });
    }
    profiles
}

fn parse_xmp2(region: &[u8]) -> Vec<Profile> {
    if region.len() < 4 {
        return Vec::new();
    }
    let enable = region[2];
    let mut profiles = Vec::new();
    for (i, off) in [9usize, 56].into_iter().enumerate() {
        let Some(mts) = xmp2_profile_mts(region, off) else {
            continue;
        };
        if enable & (1 << i) == 0 && !plausible_mts(mts) {
            continue;
        }
        profiles.push(Profile {
            kind: "XMP",
            index: (i as u8) + 1,
            name: None,
            mts,
        });
    }
    profiles
}

fn xmp2_profile_mts(region: &[u8], off: usize) -> Option<u32> {
    let mtb = *region.get(off + 3)?;
    let ftb = *region.get(off + 38)? as i8;
    let tck_ps = i32::from(mtb) * 125 + i32::from(ftb);
    (tck_ps > 0).then(|| snap_mts((2_000_000 / tck_ps) as u32))
}

fn ddr4_jedec_mts(bytes: &[u8]) -> Option<u32> {
    let mtb = *bytes.get(18)?;
    let ftb = bytes.get(125).copied().unwrap_or(0) as i8;
    let tck_ps = i32::from(mtb) * 125 + i32::from(ftb);
    (tck_ps > 0).then(|| snap_mts((2_000_000 / tck_ps) as u32))
}

fn ddr5_mts(tck_ps: u16) -> Option<u32> {
    (tck_ps > 0).then(|| snap_mts(2_000_000 / u32::from(tck_ps)))
}

fn snap_mts(raw: u32) -> u32 {
    const BINS: &[u32] = &[
        1600, 1866, 2133, 2400, 2666, 2933, 3200, 3333, 3466, 3600, 3733, 3866, 4000, 4133, 4266,
        4400, 4600, 4800, 5000, 5200, 5400, 5600, 5800, 6000, 6200, 6400, 6600, 6800, 7000, 7200,
        7400, 7600, 7800, 8000, 8200, 8400, 8600, 8800, 9000, 9200, 9600,
    ];
    BINS.iter()
        .copied()
        .min_by_key(|bin| bin.abs_diff(raw))
        .filter(|bin| bin.abs_diff(raw) <= raw / 40 + 30)
        .unwrap_or(raw)
}

fn plausible_mts(mts: u32) -> bool {
    (1600..=12000).contains(&mts)
}

fn matches_rate(operating: u32, profile: u32) -> bool {
    operating.abs_diff(profile) <= 100
}

fn u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn ascii_name(bytes: &[u8]) -> Option<String> {
    let name: String = bytes
        .iter()
        .copied()
        .take_while(|b| *b != 0)
        .map(char::from)
        .collect();
    let name = name.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        None
    } else {
        Some(name.to_string())
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snaps_common_ddr_bins() {
        assert_eq!(snap_mts(3597), 3600);
        assert_eq!(snap_mts(6006), 6000);
        assert_eq!(snap_mts(4796), 4800);
        assert_eq!(snap_mts(2932), 2933);
    }

    #[test]
    fn ddr4_xmp2_profile_speed() {
        let mut spd = vec![0; 512];
        spd[2] = DDR4;
        spd[18] = 10; // 10 * 125ps = 1250ps → DDR4-1600
        spd[DDR4_XMP_OFF] = XMP_MAGIC[0];
        spd[DDR4_XMP_OFF + 1] = XMP_MAGIC[1];
        spd[DDR4_XMP_OFF + 2] = 0x01;
        spd[DDR4_XMP_OFF + 9 + 3] = 4; // 500ps
        spd[DDR4_XMP_OFF + 9 + 38] = 56u8; // +56ps → 556ps ≈ DDR4-3600
        let info = decode_spd(&spd).unwrap();
        assert_eq!(info.jedec_mts, Some(1600));
        assert_eq!(info.profiles.len(), 1);
        assert_eq!(info.profiles[0].kind, "XMP");
        assert_eq!(info.profiles[0].mts, 3600);
    }

    #[test]
    fn ddr5_xmp_and_expo_speeds() {
        let mut spd = vec![0; 1024];
        spd[2] = DDR5;
        spd[20..22].copy_from_slice(&417u16.to_le_bytes());
        spd[DDR5_VENDOR_OFF] = XMP_MAGIC[0];
        spd[DDR5_VENDOR_OFF + 1] = XMP_MAGIC[1];
        spd[DDR5_VENDOR_OFF + 2] = 0x30;
        spd[DDR5_VENDOR_OFF + 3] = 0x01;
        let name = b"TG-6000";
        spd[DDR5_VENDOR_OFF + 0x0e..DDR5_VENDOR_OFF + 0x0e + name.len()].copy_from_slice(name);
        let p1 = DDR5_VENDOR_OFF + XMP3_HEADER_LEN;
        spd[p1 + 5..p1 + 7].copy_from_slice(&333u16.to_le_bytes());
        let expo = DDR5_VENDOR_OFF + XMP3_HEADER_LEN + 2 * XMP3_PROFILE_LEN;
        spd[expo..expo + 4].copy_from_slice(EXPO_MAGIC);
        spd[expo + 5] = 0x01;
        spd[expo + EXPO_HEADER_LEN + 4..expo + EXPO_HEADER_LEN + 6]
            .copy_from_slice(&333u16.to_le_bytes());
        let info = decode_spd(&spd).unwrap();
        assert_eq!(info.jedec_mts, Some(4800));
        assert!(info
            .profiles
            .iter()
            .any(|p| p.kind == "XMP" && p.mts == 6000));
        assert!(info
            .profiles
            .iter()
            .any(|p| p.kind == "EXPO" && p.mts == 6000));
        assert_eq!(
            info.profiles
                .iter()
                .find(|p| p.kind == "XMP")
                .unwrap()
                .name
                .as_deref(),
            Some("TG-6000")
        );
    }

    #[test]
    fn jedec_only_ddr5_has_no_profiles() {
        let mut spd = vec![0; 1024];
        spd[2] = DDR5;
        spd[20..22].copy_from_slice(&417u16.to_le_bytes());
        let info = decode_spd(&spd).unwrap();
        assert_eq!(info.jedec_mts, Some(4800));
        assert!(info.profiles.is_empty());
    }
}
