//! CPU memory-channel capability and observable topology.
//!
//! x86 CPUID does not provide a universal "number of memory channels" field. This
//! probe therefore combines the processor brand/class with the DMI board family and
//! labels the result as inferred. EDAC instances are reported separately as observed
//! kernel topology; they are not silently equated with populated/active channels.

use std::path::Path;

use crate::model::{Detection, Status};
use crate::probes::{Context, Probe, ProbeResult};

const SRC: &str = "memory-topology";
const FEATURES: &[&str] = &["memory_channels"];

pub struct MemoryProbe;

impl Probe for MemoryProbe {
    fn name(&self) -> &'static str {
        SRC
    }

    fn feature_ids(&self) -> Vec<&'static str> {
        FEATURES.to_vec()
    }

    fn detect(&self, ctx: &Context) -> ProbeResult {
        let cpu = cpu_identity(ctx);
        let board = read_trim(ctx, "/sys/class/dmi/id/board_name").unwrap_or_default();
        let capability = infer_channels(cpu.as_ref(), &board);
        let edac = edac_instances(ctx);

        let detection = match capability {
            Some(capability) => {
                let mut detail = format!(
                    "{} memory channel(s) per CPU socket maximum (inferred from {})",
                    capability.channels, capability.basis
                );
                if capability.ddr5 {
                    detail.push_str(&format!(
                        "; DDR5 presents {} × 32-bit subchannels",
                        capability.channels * 2
                    ));
                }
                match edac {
                    Ok(0) => detail.push_str("; active-channel telemetry unavailable (no EDAC memory-controller instances)"),
                    Ok(count) => detail.push_str(&format!(
                        "; Linux EDAC exposes {count} memory-controller instance(s), which may not equal populated channels"
                    )),
                    Err(reason) => detail.push_str(&format!("; EDAC topology unavailable: {reason}")),
                }
                Detection::with_detail(Status::Present, SRC, detail)
            }
            None => {
                let detail = match edac {
                    Ok(count) if count > 0 => format!(
                        "CPU channel maximum unknown; Linux EDAC exposes {count} memory-controller instance(s)"
                    ),
                    Ok(_) => "CPU channel maximum unknown; no EDAC memory-controller instances".to_string(),
                    Err(reason) => format!("CPU channel maximum unknown; EDAC topology unavailable: {reason}"),
                };
                Detection::with_detail(Status::Unknown, SRC, detail)
            }
        };
        Ok(vec![("memory_channels", detection)])
    }
}

#[derive(Debug)]
struct CpuIdentity {
    vendor: String,
    brand: String,
    family: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct ChannelCapability {
    channels: usize,
    ddr5: bool,
    basis: &'static str,
}

fn cpu_identity(ctx: &Context) -> Option<CpuIdentity> {
    let text = ctx.reader.read_to_string(Path::new("/proc/cpuinfo")).ok()?;
    let block = text.split("\n\n").find(|block| {
        block.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(key, _)| key.trim() == "processor")
        })
    })?;
    let field = |name: &str| {
        block.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then(|| value.trim().to_string())
        })
    };
    Some(CpuIdentity {
        vendor: field("vendor_id")?,
        brand: field("model name")?,
        family: field("cpu family")?.parse().ok()?,
    })
}

fn infer_channels(cpu: Option<&CpuIdentity>, board: &str) -> Option<ChannelCapability> {
    let cpu = cpu?;
    if !matches!(cpu.vendor.as_str(), "AuthenticAMD" | "HygonGenuine") {
        return None;
    }
    let brand = cpu.brand.to_ascii_uppercase();
    let board = board.to_ascii_uppercase();

    // Workstation platforms expose their channel count most reliably through the
    // board/chipset class. A PRO CPU can operate in either TRX50 or WRX90.
    if board.contains("WRX90") || board.contains("WRX80") {
        return Some(capability(
            8,
            board.contains("WRX90"),
            "WRX90/WRX80 workstation platform class",
        ));
    }
    if board.contains("TRX50") || board.contains("TRX40") || board.contains("X399") {
        return Some(capability(
            4,
            board.contains("TRX50"),
            "Threadripper workstation platform class",
        ));
    }

    if brand.contains("EPYC") {
        return infer_epyc(&brand);
    }
    if brand.contains("THREADRIPPER") {
        // Without a board-class identifier, PRO parts are ambiguous between TRX50
        // (4 channels) and WRX90 (8 channels).
        return None;
    }
    if brand.contains("RYZEN AI MAX") {
        // These products use a wider LPDDR interface; do not force it into the
        // conventional desktop dual-channel model without an exact product table.
        return None;
    }
    if brand.contains("RYZEN") {
        let ddr5 = cpu.family >= 0x1a || is_am5_board(&board);
        return Some(capability(2, ddr5, "AMD Ryzen client product class"));
    }
    None
}

fn infer_epyc(brand: &str) -> Option<ChannelCapability> {
    let model = brand
        .split_whitespace()
        .find(|word| word.chars().filter(char::is_ascii_digit).count() >= 4)?;
    let digits: String = model.chars().filter(char::is_ascii_digit).collect();
    let first = digits.chars().next()?;
    let generation = digits.chars().last()?;
    match (first, generation) {
        ('8', '4') => Some(capability(6, true, "AMD EPYC 8004 product series")),
        ('9', '4' | '5') => Some(capability(12, true, "AMD EPYC 9004/9005 product series")),
        ('7', '1' | '2' | '3') => Some(capability(
            8,
            false,
            "AMD EPYC 7001/7002/7003 product series",
        )),
        _ => None,
    }
}

fn capability(channels: usize, ddr5: bool, basis: &'static str) -> ChannelCapability {
    ChannelCapability {
        channels,
        ddr5,
        basis,
    }
}

fn is_am5_board(board: &str) -> bool {
    [
        "X870E", "X870", "B850", "B840", "X670E", "X670", "B650E", "B650", "A620",
    ]
    .iter()
    .any(|name| board.contains(name))
}

fn edac_instances(ctx: &Context) -> Result<usize, String> {
    let entries = ctx
        .reader
        .read_dir(Path::new("/sys/devices/system/edac/mc"))
        .map_err(|error| error.to_string())?;
    let mut count = 0;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_name
            .strip_prefix("mc")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        {
            count += 1;
        }
    }
    Ok(count)
}

fn read_trim(ctx: &Context, path: &str) -> Option<String> {
    ctx.reader
        .read_to_string(Path::new(path))
        .ok()
        .map(|value| value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(brand: &str, family: u32) -> CpuIdentity {
        CpuIdentity {
            vendor: "AuthenticAMD".into(),
            brand: brand.into(),
            family,
        }
    }

    #[test]
    fn desktop_ryzen_is_dual_channel() {
        let result = infer_channels(
            Some(&cpu("AMD Ryzen 7 9800X3D 8-Core Processor", 0x1a)),
            "PRO X870-P WIFI",
        )
        .unwrap();
        assert_eq!(result.channels, 2);
        assert!(result.ddr5);
    }

    #[test]
    fn threadripper_uses_board_platform_width() {
        let processor = cpu("AMD Ryzen Threadripper PRO 7995WX", 0x19);
        assert_eq!(
            infer_channels(Some(&processor), "WRX90").unwrap().channels,
            8
        );
        assert_eq!(
            infer_channels(Some(&processor), "TRX50").unwrap().channels,
            4
        );
        assert_eq!(infer_channels(Some(&processor), "unknown"), None);
    }

    #[test]
    fn epyc_series_distinguish_channel_counts() {
        assert_eq!(
            infer_channels(Some(&cpu("AMD EPYC 9654", 0x19)), "")
                .unwrap()
                .channels,
            12
        );
        assert_eq!(
            infer_channels(Some(&cpu("AMD EPYC 8534P", 0x19)), "")
                .unwrap()
                .channels,
            6
        );
        assert_eq!(
            infer_channels(Some(&cpu("AMD EPYC 7763", 0x19)), "")
                .unwrap()
                .channels,
            8
        );
    }
}
