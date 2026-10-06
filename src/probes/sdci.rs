//! Read-only SDCI prerequisites, not an end-to-end SDCI support test.
//! PCI register encodings follow include/uapi/linux/pci_regs.h; see
//! https://docs.kernel.org/PCI/tph.html for driver/firmware requirements.
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::model::{Detection, Status};
use crate::probes::{finding_detail, Context, Findings, Probe, ProbeResult};

const SRC: &str = "sdci";
const IDS: &[&str] = &[
    "sdci_roots",
    "sdci_devices",
    "sdci_kernel",
    "sdci_firmware",
    "sdci_active",
];

pub struct SdciProbe;
impl Probe for SdciProbe {
    fn name(&self) -> &'static str {
        SRC
    }
    fn feature_ids(&self) -> Vec<&'static str> {
        IDS.to_vec()
    }
    fn detect(&self, ctx: &Context) -> ProbeResult {
        let mut out = pci_findings(ctx);
        out.push(("sdci_kernel", kernel(ctx)));
        out.push(finding_detail(SRC, "sdci_firmware", Status::Unknown,
            "BIOS SDCI setting and ACPI cache-locality _DSM results are not exposed by this probe; chipset name or PCIe switch presence does not prove support"));
        out.push(finding_detail(SRC, "sdci_active", Status::Unknown,
            "Not measured: CPU SDCIAE and PCIe TPH capabilities do not prove active cache injection; platform firmware and a cooperating device/driver are required"));
        Ok(out)
    }
}

fn kernel(ctx: &Context) -> Detection {
    let cmdline = ctx.reader.read_to_string(Path::new("/proc/cmdline"));
    if cmdline.as_ref().is_ok_and(|s| {
        s.split_whitespace()
            .take_while(|s| *s != "--")
            .any(|s| s == "notph")
    }) {
        return Detection::with_detail(
            Status::Disabled,
            SRC,
            "/proc/cmdline: notph disables TPH system-wide",
        );
    }
    let release = ctx
        .reader
        .read_to_string(Path::new("/proc/sys/kernel/osrelease"));
    if let Ok(release) = release {
        let release = release.trim();
        if !release.is_empty() && !release.contains('/') && release != "." && release != ".." {
            let path = format!("/boot/config-{release}");
            if let Ok(config) = ctx.reader.read_to_string(Path::new(&path)) {
                if config.lines().any(|s| s == "CONFIG_PCIE_TPH=y") {
                    return Detection::with_detail(
                        Status::Present,
                        SRC,
                        format!(
                            "{path}: CONFIG_PCIE_TPH=y; {}; driver enablement is separate",
                            if cmdline.is_ok() {
                                "no notph boot option"
                            } else {
                                "boot policy unreadable"
                            }
                        ),
                    );
                }
                if config
                    .lines()
                    .any(|s| s == "# CONFIG_PCIE_TPH is not set" || s == "CONFIG_PCIE_TPH=n")
                {
                    return Detection::with_detail(
                        Status::Disabled,
                        SRC,
                        format!("{path}: CONFIG_PCIE_TPH disabled"),
                    );
                }
            }
        }
    }
    Detection::with_detail(Status::Unknown, SRC,
        "Running-kernel CONFIG_PCIE_TPH unavailable; kernel version alone does not establish support")
}

fn word(data: &[u8], offset: usize) -> Result<u16, &'static str> {
    let b = data
        .get(offset..offset + 2)
        .ok_or("configuration truncated (root may be required)")?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn dword(data: &[u8], offset: usize) -> Result<u32, &'static str> {
    let b = data
        .get(offset..offset + 4)
        .ok_or("configuration truncated (root may be required)")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Traverse the conventional capability chain without assuming its layout.
fn pcie(data: &[u8]) -> Result<Option<usize>, &'static str> {
    if data.len() < 64 {
        return Err("configuration header truncated");
    }
    if matches!(word(data, 0)?, 0 | 0xffff) {
        return Err("device unavailable");
    }
    if word(data, 6)? & 0x10 == 0 {
        return Ok(None);
    }
    let pointer = match data[0x0e] & 0x7f {
        0 | 1 => 0x34,
        2 => 0x14,
        _ => return Err("invalid PCI header type"),
    };
    let mut offset = usize::from(data[pointer]);
    let mut seen = HashSet::new();
    let mut found = None;
    while offset != 0 {
        if !(0x40..=0xfc).contains(&offset) || offset % 4 != 0 || !seen.insert(offset) {
            return Err("malformed conventional capability chain");
        }
        let header = word(data, offset)?;
        if header & 0xff == 0x10 {
            found = Some(offset);
        }
        offset = usize::from(header >> 8);
    }
    Ok(found)
}

fn requester(data: &[u8]) -> Result<Option<(u32, u32)>, &'static str> {
    let mut offset = 0x100;
    let mut seen = HashSet::new();
    let mut found = None;
    loop {
        if !(0x100..=0xffc).contains(&offset) || offset % 4 != 0 || !seen.insert(offset) {
            return Err("malformed extended capability chain");
        }
        let header = dword(data, offset)?;
        if header == 0 {
            return if offset == 0x100 {
                Ok(None)
            } else {
                Err("empty linked capability")
            };
        }
        if header == u32::MAX {
            return Err("extended configuration unavailable");
        }
        if header & 0xffff == 0x17 {
            if found.is_some() || offset > 0xff4 {
                return Err("malformed TPH capability");
            }
            found = Some((dword(data, offset + 4)?, dword(data, offset + 8)?));
        }
        let next = (header >> 20) as usize;
        if next == 0 {
            return Ok(found);
        }
        offset = next;
    }
}

#[derive(Default)]
struct Inventory {
    lines: Vec<String>,
    errors: Vec<String>,
    states: Vec<Status>,
}
impl Inventory {
    fn finish(self, kind: &str) -> Detection {
        let status = if !self.errors.is_empty() {
            Status::Unknown
        } else if self.states.is_empty() {
            Status::Absent
        } else if self.states.iter().all(|s| *s == self.states[0]) {
            self.states[0]
        } else {
            Status::Unknown
        };
        let mut lines = self.lines;
        if lines.is_empty() {
            lines.push(format!("No {kind} observed in readable configuration"));
        }
        if !self.errors.is_empty() {
            let mut grouped: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for error in &self.errors {
                let (device, reason) = error.split_once(": ").unwrap_or(("PCI", error));
                grouped.entry(reason).or_default().push(device);
            }
            for (reason, devices) in grouped {
                lines.push(format!("Incomplete: {reason}: {}", devices.join(", ")));
            }
        }
        if status == Status::Unknown && self.errors.is_empty() {
            lines.push("Mixed or unresolved device states; see individual functions above".into());
        }
        Detection::with_detail(status, SRC, lines.join("\n"))
    }
}

fn pci_findings(ctx: &Context) -> Findings {
    let mut roots = Inventory::default();
    let mut devices = Inventory::default();
    let entries = ctx.reader.read_dir(Path::new("/sys/bus/pci/devices"));
    match entries {
        Err(e) => {
            roots.errors.push(format!("PCI enumeration: {e}"));
            devices.errors.push(format!("PCI enumeration: {e}"));
        }
        Ok(mut entries) => {
            entries.sort_by_key(|e| e.as_ref().map(|e| e.file_name.clone()).unwrap_or_default());
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        roots.errors.push(format!("PCI entry: {e}"));
                        devices.errors.push(format!("PCI entry: {e}"));
                        continue;
                    }
                };
                let data = match ctx.reader.read(&entry.path.join("config")) {
                    Ok(data) => data,
                    Err(e) => {
                        let error = format!("{}: {e}", entry.file_name);
                        roots.errors.push(error.clone());
                        devices.errors.push(error);
                        continue;
                    }
                };
                let cap = match pcie(&data) {
                    Ok(Some(cap)) => cap,
                    Ok(None) => continue,
                    Err(e) => {
                        let error = format!("{}: {e}", entry.file_name);
                        roots.errors.push(error.clone());
                        devices.errors.push(error);
                        continue;
                    }
                };
                match word(&data, cap + 2) {
                    Ok(flags) if (flags >> 4) & 0xf == 4 => match root_support(&data, cap, flags) {
                        Ok((state, detail)) => {
                            roots.states.push(state);
                            roots.lines.push(format!("{}: {detail}", entry.file_name));
                        }
                        Err(e) => roots.errors.push(format!("{}: {e}", entry.file_name)),
                    },
                    Ok(_) => {}
                    Err(e) => roots.errors.push(format!("{}: {e}", entry.file_name)),
                }
                match requester(&data) {
                    Ok(Some((capability, control))) => {
                        let (state, detail) = requester_state(capability, control);
                        devices.states.push(state);
                        let driver = ctx
                            .reader
                            .read_link(&entry.path.join("driver"))
                            .ok()
                            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                            .unwrap_or_else(|| "unbound or unavailable".into());
                        devices
                            .lines
                            .push(format!("{}: {detail}; driver {driver}", entry.file_name));
                    }
                    Ok(None) => {}
                    Err(e) => devices.errors.push(format!("{}: {e}", entry.file_name)),
                }
            }
        }
    }
    vec![
        ("sdci_roots", roots.finish("root-port TPH capabilities")),
        ("sdci_devices", devices.finish("TPH requesters")),
    ]
}

fn root_support(
    data: &[u8],
    cap: usize,
    flags: u16,
) -> Result<(Status, &'static str), &'static str> {
    if flags & 0xf < 2 {
        return Ok((Status::Absent, "PCIe v1; no TPH completer capability"));
    }
    match (dword(data, cap + 0x24)? >> 12) & 3 {
        0 => Ok((Status::Absent, "TPH completer unsupported")),
        1 => Ok((
            Status::Present,
            "TPH completer supported; extended TPH unsupported",
        )),
        3 => Ok((Status::Present, "TPH and extended TPH completer supported")),
        _ => Err("reserved TPH completer encoding"),
    }
}

fn requester_state(cap: u32, ctrl: u32) -> (Status, String) {
    let modes = [
        (1, "No ST"),
        (2, "Interrupt Vector"),
        (4, "Device Specific"),
    ]
    .into_iter()
    .filter(|(mask, _)| cap & mask != 0)
    .map(|(_, name)| name)
    .collect::<Vec<_>>();
    let mode = ctrl & 7;
    let request = (ctrl >> 8) & 3;
    let valid = cap & 7 != 0
        && request != 2
        && (request != 3 || cap & 0x100 != 0)
        && (request == 0 || (mode < 3 && cap & (1 << mode) != 0));
    let state = if !valid {
        Status::Unknown
    } else if request == 0 {
        Status::Disabled
    } else {
        Status::Enabled
    };
    (state, format!("TPH requester supported; modes [{}]; requester {}; selected mode {}; capability=0x{cap:08x}, control=0x{ctrl:08x}",
        modes.join(", "), state.label(), match mode { 0 => "No ST", 1 => "Interrupt Vector", 2 => "Device Specific", _ => "reserved" }))
}
