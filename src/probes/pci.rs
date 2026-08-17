//! AMD PCI inventory probe.

use crate::model::{Detection, Status};
use crate::probes::gpu::{self, GpuPci};
use crate::probes::{unavailable, Context, Probe, ProbeResult};
use std::path::{Path, PathBuf};

const SRC: &str = "pci";
const AMD: u32 = 0x1022;
const ATI: u32 = 0x1002;

fn all_feature_ids() -> Vec<&'static str> {
    let mut ids = gpu::FEATURES.to_vec();
    ids.extend(RULES.iter().map(|rule| rule.feature));
    ids
}

pub struct PciProbe;
impl Probe for PciProbe {
    fn name(&self) -> &'static str {
        SRC
    }
    fn feature_ids(&self) -> Vec<&'static str> {
        all_feature_ids()
    }
    fn detect(&self, ctx: &Context) -> ProbeResult {
        let (devices, complete) = match scan_amd_devices(ctx) {
            Ok(value) => value,
            Err(reason) => return Ok(unavailable(SRC, &all_feature_ids(), reason)),
        };
        let mut out: Vec<_> = RULES
            .iter()
            .map(|rule| {
                let detection = if rule.feature == "chipset" {
                    identify_chipset(ctx, &devices, complete)
                } else {
                    evaluate(rule, &devices, complete)
                };
                (rule.feature, detection)
            })
            .collect();
        let gpus: Vec<GpuPci> = devices
            .iter()
            .map(|device| GpuPci {
                path: device.path.clone(),
                vendor: device.vendor,
                device: device.device,
                class_hi: device.class_hi,
                driver: device.driver.clone(),
                driver_known: device.driver_known,
            })
            .collect();
        out.extend(gpu::findings(ctx, &gpus, complete));
        Ok(out)
    }
}

struct PciDevice {
    path: PathBuf,
    vendor: u16,
    device: u16,
    class_hi: u8,
    subclass: u8,
    driver: Option<String>,
    driver_known: bool,
}
struct Rule {
    feature: &'static str,
    class: Option<(u8, u8)>,
    devices: &'static [u16],
    drivers: &'static [&'static str],
}

#[rustfmt::skip]
const RULES: &[Rule] = &[
    Rule { feature:"npu",      class:None, devices:&[0x1502,0x17f0,0x17f1], drivers:&["amdxdna"] },
    Rule { feature:"psp",      class:Some((0x10,0xff)), devices:&[0x1456,0x1486,0x15df,0x1649], drivers:&["ccp"] },
    Rule { feature:"chipset",  class:Some((0x06,0xff)), devices:&[], drivers:&["pcieport"] },
    Rule { feature:"ethernet", class:Some((0x02,0x00)), devices:&[], drivers:&["amd-xgbe", "xgbe"] },
    Rule { feature:"audio",    class:Some((0x04,0x03)), devices:&[], drivers:&["snd_hda_intel", "snd_pci_acp3x", "snd_pci_acp5x", "snd_pci_acp6x"] },
    Rule { feature:"smbus",    class:Some((0x0c,0x05)), devices:&[], drivers:&["piix4_smbus"] },
    Rule { feature:"usb",      class:Some((0x0c,0x03)), devices:&[], drivers:&["xhci_hcd"] },
    Rule { feature:"sata",     class:Some((0x01,0x06)), devices:&[], drivers:&["ahci"] },
    Rule { feature:"nvme",     class:Some((0x01,0x08)), devices:&[], drivers:&["nvme"] },
];

fn evaluate(rule: &Rule, devices: &[PciDevice], complete: bool) -> Detection {
    let matches: Vec<_> = devices
        .iter()
        .filter(|device| matches_rule(device, rule))
        .collect();
    let Some(best) = matches
        .iter()
        .find(|d| d.driver.is_some())
        .copied()
        .or_else(|| matches.first().copied())
    else {
        return Detection::with_detail(
            if complete {
                Status::Absent
            } else {
                Status::Unknown
            },
            SRC,
            if complete {
                "no matching AMD PCI function"
            } else {
                "PCI enumeration incomplete; an unreadable function could match"
            },
        );
    };
    let status = if best.driver.is_some() {
        Status::Enabled
    } else if best.driver_known {
        Status::Present
    } else {
        Status::Unknown
    };
    let mut detail = format!("{:04x}:{:04x}", best.vendor, best.device);
    if let Some(driver) = &best.driver {
        detail.push_str(&format!(", driver {driver}"));
    }
    if matches.len() > 1 {
        detail.push_str(&format!(" (+{} more)", matches.len() - 1));
    }
    Detection::with_detail(status, SRC, detail)
}

fn identify_chipset(ctx: &Context, devices: &[PciDevice], complete: bool) -> Detection {
    let board = ctx
        .reader
        .read_to_string(Path::new("/sys/class/dmi/id/board_name"))
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());
    let exact = board.as_deref().and_then(chipset_from_board);
    let mut functions: Vec<_> = devices
        .iter()
        .filter(|device| (0x43b0..=0x43ff).contains(&device.device))
        .collect();
    functions.sort_by_key(|device| device.device);
    functions.dedup_by_key(|device| device.device);

    if exact.is_none() && functions.is_empty() {
        return Detection::with_detail(
            if complete {
                Status::Absent
            } else {
                Status::Unknown
            },
            SRC,
            if complete {
                "no AMD Promontory PCI functions and no chipset name in DMI"
            } else {
                "PCI enumeration incomplete and no chipset name in DMI"
            },
        );
    }

    let status = if functions.iter().any(|device| device.driver.is_some()) {
        Status::Enabled
    } else if functions.iter().any(|device| !device.driver_known) {
        Status::Unknown
    } else {
        Status::Present
    };
    let ids = functions
        .iter()
        .map(|device| format!("{:04x}:{:04x}", device.vendor, device.device))
        .collect::<Vec<_>>()
        .join(", ");

    let detail = if let Some(chipset) = exact {
        let board = board.as_deref().unwrap_or_default();
        if ids.is_empty() {
            format!("AMD {chipset} chipset (DMI board {board:?}; PCI corroboration unavailable)")
        } else {
            format!(
                "AMD {chipset} chipset (high confidence: DMI board {board:?}; Promontory PCI {ids})"
            )
        }
    } else if functions.iter().any(|device| device.device == 0x43fc) {
        format!(
            "AMD 800 Series chipset family (PCI {ids}; exact retail SKU unavailable because Promontory IDs are shared)"
        )
    } else {
        format!(
            "AMD Promontory chipset family (PCI {ids}; exact generation/SKU unavailable from shared IDs)"
        )
    };
    Detection::with_detail(status, SRC, detail)
}

fn chipset_from_board(board: &str) -> Option<&'static str> {
    let board = board.to_ascii_uppercase();
    [
        "X870E", "X870", "B850", "B840", "X670E", "X670", "B650E", "B650", "A620", "WRX90",
        "TRX50", "WRX80", "TRX40", "X570", "B550", "A520", "X470", "B450", "X399", "X370", "B350",
        "A320",
    ]
    .into_iter()
    .find(|chipset| board.contains(chipset))
}

fn matches_rule(device: &PciDevice, rule: &Rule) -> bool {
    rule.class.is_some_and(|(class, sub)| {
        device.class_hi == class && (sub == 0xff || device.subclass == sub)
    }) || rule.devices.contains(&device.device)
        || device
            .driver
            .as_deref()
            .is_some_and(|driver| rule.drivers.contains(&driver))
}

fn scan_amd_devices(ctx: &Context) -> Result<(Vec<PciDevice>, bool), String> {
    let entries = ctx
        .reader
        .read_dir(Path::new("/sys/bus/pci/devices"))
        .map_err(|e| format!("cannot inspect PCI devices: {e}"))?;
    let mut devices = Vec::new();
    let mut complete = true;
    for entry in entries {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        let path = entry.path;
        let vendor = match read_hex(ctx, &path.join("vendor")) {
            Ok(value) => value,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        if !matches!(vendor, AMD | ATI) {
            continue;
        }
        let (device, class) = match (
            read_hex(ctx, &path.join("device")),
            read_hex(ctx, &path.join("class")),
        ) {
            (Ok(device), Ok(class)) => (device as u16, class),
            _ => {
                complete = false;
                continue;
            }
        };
        let (driver, driver_known) = match ctx.reader.read_link(&path.join("driver")) {
            Ok(path) => (
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
                true,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, true),
            Err(_) => {
                complete = false;
                (None, false)
            }
        };
        devices.push(PciDevice {
            path,
            vendor: vendor as u16,
            device,
            class_hi: ((class >> 16) & 0xff) as u8,
            subclass: ((class >> 8) & 0xff) as u8,
            driver,
            driver_known,
        });
    }
    Ok((devices, complete))
}

fn read_hex(ctx: &Context, path: &Path) -> Result<u32, String> {
    let text = ctx.reader.read_to_string(path).map_err(|e| e.to_string())?;
    u32::from_str_radix(text.trim().strip_prefix("0x").unwrap_or(text.trim()), 16)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dev(class: u8, sub: u8, driver: Option<&str>) -> PciDevice {
        PciDevice {
            path: PathBuf::new(),
            vendor: AMD as u16,
            device: 1,
            class_hi: class,
            subclass: sub,
            driver: driver.map(str::to_string),
            driver_known: true,
        }
    }
    fn rule(id: &str) -> &'static Rule {
        RULES.iter().find(|rule| rule.feature == id).unwrap()
    }
    #[test]
    fn display_class_does_not_claim_npu() {
        assert!(!matches_rule(&dev(3, 0, None), rule("npu")));
    }
    #[test]
    fn network_subclasses_do_not_mix() {
        assert!(matches_rule(&dev(2, 0, None), rule("ethernet")));
        assert!(!matches_rule(&dev(2, 0x80, None), rule("ethernet")));
    }
    #[test]
    fn amdxdna_driver_matches_npu() {
        assert!(matches_rule(&dev(0x12, 0, Some("amdxdna")), rule("npu")));
    }

    #[test]
    fn dmi_board_names_identify_exact_chipsets() {
        assert_eq!(chipset_from_board("PRO X870-P WIFI"), Some("X870"));
        assert_eq!(chipset_from_board("Creator WRX90"), Some("WRX90"));
        assert_eq!(chipset_from_board("Generic Board"), None);
    }
}
