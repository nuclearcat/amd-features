//! AMD GPU classification and runtime inventory (iGPU vs dGPU, VRAM, ReBAR/SAM, VCN, ROCm).

use std::path::{Path, PathBuf};

use crate::model::{Detection, Status};
use crate::probes::{finding_detail, Context, Findings};

const SRC: &str = "pci";
const ATI: u16 = 0x1002;
const NPU_IDS: &[u16] = &[0x1502, 0x17f0, 0x17f1];

pub(crate) const FEATURES: &[&str] = &["igpu", "dgpu", "gpu_vram", "rebar", "vcn", "rocm"];

pub(crate) struct GpuPci {
    pub path: PathBuf,
    pub vendor: u16,
    pub device: u16,
    pub class_hi: u8,
    pub driver: Option<String>,
    pub driver_known: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Integrated,
    Discrete,
    Unknown,
}

struct GpuView {
    pci: String,
    kind: Kind,
    detail: String,
    status: Status,
    vram: Option<u64>,
    gtt: Option<u64>,
    vcn: Option<String>,
    rebar: Option<(Status, String)>,
}

pub(crate) fn findings(ctx: &Context, devices: &[GpuPci], complete: bool) -> Findings {
    let kfd = kfd_nodes(ctx);
    let gpus: Vec<GpuView> = devices
        .iter()
        .filter(|device| is_gpu(device))
        .map(|device| inspect(ctx, device, &kfd))
        .collect();

    let mut out = Vec::new();
    push_kind(
        &mut out,
        "igpu",
        Kind::Integrated,
        &gpus,
        complete,
        "no AMD integrated display controller",
    );
    push_kind(
        &mut out,
        "dgpu",
        Kind::Discrete,
        &gpus,
        complete,
        "no AMD discrete GPU",
    );
    if gpus.iter().any(|gpu| gpu.kind == Kind::Unknown) && complete {
        let ids: Vec<_> = gpus
            .iter()
            .filter(|gpu| gpu.kind == Kind::Unknown)
            .map(|gpu| gpu.pci.as_str())
            .collect();
        let note = format!(
            "unclassified AMD display function(s) {}; iGPU vs dGPU not determined",
            ids.join(", ")
        );
        if !gpus.iter().any(|gpu| gpu.kind == Kind::Integrated) {
            replace_unknown_note(&mut out, "igpu", &note);
        }
        if !gpus.iter().any(|gpu| gpu.kind == Kind::Discrete) {
            replace_unknown_note(&mut out, "dgpu", &note);
        }
    }

    out.push(vram_finding(&gpus, complete));
    out.push(rebar_finding(&gpus, complete));
    out.push(vcn_finding(ctx, &gpus, complete));
    out.push(rocm_finding(ctx, &kfd, complete));
    out
}

fn is_gpu(device: &GpuPci) -> bool {
    if device.vendor != ATI {
        return false;
    }
    if NPU_IDS.contains(&device.device) || device.driver.as_deref() == Some("amdxdna") {
        return false;
    }
    device.class_hi == 0x03 || matches!(device.driver.as_deref(), Some("amdgpu" | "radeon"))
}

fn inspect(ctx: &Context, device: &GpuPci, kfd: &[KfdNode]) -> GpuView {
    let pci = format!("{:04x}:{:04x}", device.vendor, device.device);
    let mem = drm_mem(ctx, &device.path);
    let kfd_node = match_kfd(device, kfd);
    let kind = classify(ctx, device, &mem, kfd_node);
    let status = if device.driver.is_some() {
        Status::Enabled
    } else if device.driver_known {
        Status::Present
    } else {
        Status::Unknown
    };
    GpuView {
        pci,
        kind,
        detail: summarize(ctx, device, kind, &mem, kfd_node),
        status,
        vram: mem.vram,
        gtt: mem.gtt,
        vcn: video_ip(ctx, &device.path),
        rebar: rebar_for(kind, &mem, ctx, &device.path),
    }
}

fn classify(ctx: &Context, device: &GpuPci, mem: &DrmMem, kfd: Option<&KfdNode>) -> Kind {
    if let Some(node) = kfd {
        if node.simd_count > 0 {
            return if node.cpu_cores > 0 {
                Kind::Integrated
            } else {
                Kind::Discrete
            };
        }
    }
    if apu_name(device.device).is_some() {
        return Kind::Integrated;
    }
    if ctx.reader.exists(&device.path.join("board_info"))
        || ctx.reader.exists(&device.path.join("product_name"))
    {
        return Kind::Discrete;
    }
    if ctx.reader.exists(&device.path.join("uma/carveout"))
        || ctx.reader.exists(&device.path.join("uma/carveout_options"))
    {
        return Kind::Integrated;
    }
    match (mem.vram, mem.gtt) {
        (Some(vram), Some(gtt)) if gtt > vram.saturating_mul(2) && vram < 4 * GIB => {
            Kind::Integrated
        }
        (Some(vram), _) if vram >= 4 * GIB => Kind::Discrete,
        _ => Kind::Unknown,
    }
}

fn summarize(
    ctx: &Context,
    device: &GpuPci,
    kind: Kind,
    mem: &DrmMem,
    kfd: Option<&KfdNode>,
) -> String {
    let mut parts = vec![format!("{:04x}:{:04x}", device.vendor, device.device)];
    if let Some(name) = apu_name(device.device) {
        parts.push(name.to_string());
    } else if let Some(name) = read_trim(ctx, &device.path.join("product_name")) {
        parts.push(name);
    }
    match kind {
        Kind::Integrated => parts.push("integrated".into()),
        Kind::Discrete => parts.push("discrete".into()),
        Kind::Unknown => parts.push("unclassified".into()),
    }
    if let Some(driver) = &device.driver {
        parts.push(format!("driver {driver}"));
    } else if device.driver_known {
        parts.push("no driver bound".into());
    }
    if let Some(vbios) = read_trim(ctx, &device.path.join("vbios_version")) {
        parts.push(format!("VBIOS {vbios}"));
    }
    if let Some(unique) = read_trim(ctx, &device.path.join("unique_id")) {
        if unique != "0x0" && unique != "0" && unique != "0x0000000000000000" {
            parts.push(format!("unique_id {unique}"));
        }
    }
    if let Some(board) = read_trim(ctx, &device.path.join("board_info")) {
        parts.push(board.replace('\n', " "));
    }
    if let Some(vram) = mem.vram {
        let mut mem_s = format!("VRAM {}", format_bytes(vram));
        if let Some(vis) = mem.vis {
            mem_s.push_str(&format!(" (visible {})", format_bytes(vis)));
        }
        parts.push(mem_s);
    }
    if let Some(gtt) = mem.gtt {
        parts.push(format!("GTT {}", format_bytes(gtt)));
    }
    if let Some(uma) = read_trim(ctx, &device.path.join("uma/carveout_options")) {
        parts.push(format!("UMA carveout options: {}", uma.replace('\n', "; ")));
    }
    if let (Some(speed), Some(width)) = (
        read_trim(ctx, &device.path.join("current_link_speed")),
        read_trim(ctx, &device.path.join("current_link_width")),
    ) {
        let max = match (
            read_trim(ctx, &device.path.join("max_link_speed")),
            read_trim(ctx, &device.path.join("max_link_width")),
        ) {
            (Some(ms), Some(mw)) if ms != speed || mw != width => {
                format!(" (max {ms} x{mw})")
            }
            _ => String::new(),
        };
        parts.push(format!("PCIe {speed} x{width}{max}"));
    }
    if let Some(node) = kfd {
        if let Some(gfx) = node.gfx.as_deref() {
            parts.push(gfx.to_string());
        }
        if node.simd_count > 0 {
            parts.push(format!("{} SIMD", node.simd_count));
        }
        if node.clock_mhz > 0 {
            parts.push(format!("{} MHz", node.clock_mhz));
        }
    }
    parts.join(", ")
}

fn push_kind(
    out: &mut Findings,
    id: &'static str,
    kind: Kind,
    gpus: &[GpuView],
    complete: bool,
    absent: &str,
) {
    let matched: Vec<_> = gpus.iter().filter(|gpu| gpu.kind == kind).collect();
    if matched.is_empty() {
        out.push(finding_detail(
            SRC,
            id,
            if complete {
                Status::Absent
            } else {
                Status::Unknown
            },
            if complete {
                absent.to_string()
            } else {
                "PCI enumeration incomplete; an unreadable function could match".into()
            },
        ));
        return;
    }
    let status = matched
        .iter()
        .map(|gpu| gpu.status)
        .max_by_key(|status| status.rank())
        .unwrap_or(Status::Present);
    let detail = matched
        .iter()
        .map(|gpu| gpu.detail.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    out.push(finding_detail(SRC, id, status, detail));
}

fn replace_unknown_note(out: &mut Findings, id: &str, note: &str) {
    if let Some((_, detection)) = out.iter_mut().find(|(found, _)| *found == id) {
        if detection.status == Status::Absent {
            *detection = Detection::with_detail(Status::Unknown, SRC, note);
        }
    }
}

fn vram_finding(gpus: &[GpuView], complete: bool) -> (&'static str, Detection) {
    if gpus.is_empty() {
        return finding_detail(
            SRC,
            "gpu_vram",
            if complete {
                Status::Absent
            } else {
                Status::Unknown
            },
            if complete {
                "no AMD GPU"
            } else {
                "PCI enumeration incomplete"
            },
        );
    }
    let mut parts = Vec::new();
    for gpu in gpus {
        let label = match gpu.kind {
            Kind::Integrated => "iGPU",
            Kind::Discrete => "dGPU",
            Kind::Unknown => "GPU",
        };
        match (gpu.vram, gpu.gtt) {
            (Some(vram), Some(gtt)) => parts.push(format!(
                "{label} {} VRAM / {} GTT ({})",
                format_bytes(vram),
                format_bytes(gtt),
                gpu.pci
            )),
            (Some(vram), None) => {
                parts.push(format!("{label} {} VRAM ({})", format_bytes(vram), gpu.pci))
            }
            (None, Some(gtt)) => {
                parts.push(format!("{label} {} GTT ({})", format_bytes(gtt), gpu.pci))
            }
            _ => parts.push(format!("{label} memory unknown ({})", gpu.pci)),
        }
    }
    let known = gpus
        .iter()
        .any(|gpu| gpu.vram.is_some() || gpu.gtt.is_some());
    finding_detail(
        SRC,
        "gpu_vram",
        if known {
            Status::Present
        } else {
            Status::Unknown
        },
        parts.join("; "),
    )
}

fn rebar_finding(gpus: &[GpuView], complete: bool) -> (&'static str, Detection) {
    let discrete: Vec<_> = gpus
        .iter()
        .filter(|gpu| gpu.kind == Kind::Discrete)
        .collect();
    if discrete.is_empty() {
        return finding_detail(
            SRC,
            "rebar",
            if complete {
                Status::Absent
            } else {
                Status::Unknown
            },
            if complete {
                "no discrete AMD GPU (ReBAR/SAM applies to a dedicated BAR)"
            } else {
                "PCI enumeration incomplete"
            },
        );
    }
    let reports: Vec<_> = discrete
        .iter()
        .filter_map(|gpu| gpu.rebar.clone())
        .collect();
    if reports.is_empty() {
        return finding_detail(
            SRC,
            "rebar",
            Status::Unknown,
            "amdgpu did not expose visible-VRAM or BAR resize telemetry",
        );
    }
    let enabled = reports.iter().any(|(status, _)| *status == Status::Enabled);
    let disabled = reports
        .iter()
        .any(|(status, _)| *status == Status::Disabled);
    let status = if enabled && !disabled {
        Status::Enabled
    } else if disabled && !enabled {
        Status::Disabled
    } else if enabled {
        Status::Unknown
    } else {
        reports
            .iter()
            .map(|(status, _)| *status)
            .max_by_key(|status| status.rank())
            .unwrap_or(Status::Unknown)
    };
    let detail = reports
        .iter()
        .map(|(_, detail)| detail.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    finding_detail(SRC, "rebar", status, detail)
}

fn rebar_for(kind: Kind, mem: &DrmMem, ctx: &Context, path: &Path) -> Option<(Status, String)> {
    if kind != Kind::Discrete {
        return None;
    }
    if let (Some(vram), Some(vis)) = (mem.vram, mem.vis) {
        if vram <= 256 * MIB {
            return Some((
                Status::Unknown,
                format!(
                    "dedicated VRAM {} is too small to judge ReBAR",
                    format_bytes(vram)
                ),
            ));
        }
        if vis >= vram.saturating_mul(9) / 10 {
            return Some((
                Status::Enabled,
                format!(
                    "visible VRAM {} of {} (ReBAR/SAM)",
                    format_bytes(vis),
                    format_bytes(vram)
                ),
            ));
        }
        if vis <= 256 * MIB && vram > 256 * MIB {
            return Some((
                Status::Disabled,
                format!(
                    "visible VRAM {} of {} (256 MiB aperture; ReBAR/SAM off)",
                    format_bytes(vis),
                    format_bytes(vram)
                ),
            ));
        }
        return Some((
            Status::Present,
            format!(
                "visible VRAM {} of {}",
                format_bytes(vis),
                format_bytes(vram)
            ),
        ));
    }
    if ctx.reader.exists(&path.join("resource0_resize")) {
        return Some((
            Status::Present,
            "PCI BAR resize interface present; current aperture unknown".into(),
        ));
    }
    None
}

fn vcn_finding(ctx: &Context, gpus: &[GpuView], complete: bool) -> (&'static str, Detection) {
    if gpus.is_empty() {
        return finding_detail(
            SRC,
            "vcn",
            if complete {
                Status::Absent
            } else {
                Status::Unknown
            },
            if complete {
                "no AMD GPU"
            } else {
                "PCI enumeration incomplete"
            },
        );
    }
    let hits: Vec<_> = gpus.iter().filter_map(|gpu| gpu.vcn.clone()).collect();
    if !hits.is_empty() {
        return finding_detail(SRC, "vcn", Status::Enabled, hits.join("; "));
    }
    let debugfs = Path::new("/sys/kernel/debug/dri");
    match ctx.reader.metadata(debugfs) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => finding_detail(
            SRC,
            "vcn",
            Status::Unknown,
            "no debugfs DRI interface to inspect VCN/UVD firmware",
        ),
        Err(_) => finding_detail(
            SRC,
            "vcn",
            Status::Unknown,
            "cannot inspect debugfs DRI for VCN/UVD firmware",
        ),
        Ok(_) => finding_detail(
            SRC,
            "vcn",
            Status::Unknown,
            "AMD GPU present but VCN/UVD firmware files were not readable",
        ),
    }
}

fn rocm_finding(ctx: &Context, kfd: &[KfdNode], scanned_gpus: bool) -> (&'static str, Detection) {
    let path = Path::new("/dev/kfd");
    let compute: Vec<_> = kfd.iter().filter(|node| node.simd_count > 0).collect();
    match ctx.reader.metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => finding_detail(
            SRC,
            "rocm",
            if scanned_gpus {
                Status::Absent
            } else {
                Status::Unknown
            },
            "/dev/kfd absent",
        ),
        Err(error) => finding_detail(
            SRC,
            "rocm",
            Status::Unknown,
            format!("cannot inspect /dev/kfd: {error}"),
        ),
        Ok(_) => {
            let open = match ctx.reader.open_device(path, true) {
                Ok(()) => ("openable", Status::Enabled),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    ("present but not permitted", Status::Present)
                }
                Err(_) => ("present", Status::Present),
            };
            let mut detail = format!("/dev/kfd {}", open.0);
            if !compute.is_empty() {
                let nodes: Vec<_> = compute
                    .iter()
                    .map(|node| {
                        let gfx = node.gfx.as_deref().unwrap_or("gpu");
                        format!(
                            "{gfx} device {:#06x} ({} SIMD)",
                            node.device_id, node.simd_count
                        )
                    })
                    .collect();
                detail.push_str(&format!("; {}", nodes.join(", ")));
            }
            finding_detail(SRC, "rocm", open.1, detail)
        }
    }
}

struct DrmMem {
    vram: Option<u64>,
    vis: Option<u64>,
    gtt: Option<u64>,
}

fn drm_mem(ctx: &Context, path: &Path) -> DrmMem {
    DrmMem {
        vram: read_u64(ctx, &path.join("mem_info_vram_total")),
        vis: read_u64(ctx, &path.join("mem_info_vis_vram_total")),
        gtt: read_u64(ctx, &path.join("mem_info_gtt_total")),
    }
}

fn video_ip(ctx: &Context, path: &Path) -> Option<String> {
    let bdf = path.file_name()?.to_string_lossy();
    let mut candidates = vec![PathBuf::from(format!(
        "/sys/kernel/debug/dri/{bdf}/amdgpu_firmware_info"
    ))];
    if let Ok(entries) = ctx.reader.read_dir(&path.join("drm")) {
        for entry in entries.into_iter().flatten() {
            if let Some(card) = entry.file_name.strip_prefix("card") {
                if card.chars().all(|c| c.is_ascii_digit()) {
                    candidates.push(PathBuf::from(format!(
                        "/sys/kernel/debug/dri/{card}/amdgpu_firmware_info"
                    )));
                }
            }
        }
    }
    for candidate in candidates {
        if let Some(text) = read_trim(ctx, &candidate) {
            let mut blocks = Vec::new();
            for name in ["VCN", "UVD", "VCE", "JPEG"] {
                if text.to_ascii_uppercase().contains(name) {
                    blocks.push(name);
                }
            }
            if !blocks.is_empty() {
                return Some(format!("{} ({bdf})", blocks.join("/")));
            }
        }
    }
    None
}

struct KfdNode {
    device_id: u16,
    cpu_cores: u32,
    simd_count: u32,
    clock_mhz: u32,
    gfx: Option<String>,
    location: Option<u32>,
}

fn kfd_nodes(ctx: &Context) -> Vec<KfdNode> {
    let root = Path::new("/sys/class/kfd/kfd/topology/nodes");
    let Ok(entries) = ctx.reader.read_dir(root) else {
        return Vec::new();
    };
    let mut nodes = Vec::new();
    for entry in entries.into_iter().flatten() {
        let Some(text) = read_trim(ctx, &entry.path.join("properties")) else {
            continue;
        };
        let mut node = KfdNode {
            device_id: 0,
            cpu_cores: 0,
            simd_count: 0,
            clock_mhz: 0,
            gfx: None,
            location: None,
        };
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next() else { continue };
            let Some(value) = parts.next() else { continue };
            match key {
                "device_id" => node.device_id = parse_int(value) as u16,
                "cpu_cores_count" => node.cpu_cores = parse_int(value) as u32,
                "simd_count" => node.simd_count = parse_int(value) as u32,
                "max_engine_clk_fcompute" => node.clock_mhz = parse_int(value) as u32,
                "gfx_target_version" => {
                    let version = parse_int(value);
                    if version > 0 {
                        node.gfx = Some(format_gfx(version));
                    }
                }
                "location_id" => node.location = Some(parse_int(value) as u32),
                _ => {}
            }
        }
        if node.device_id != 0 || node.simd_count > 0 {
            nodes.push(node);
        }
    }
    nodes
}

fn match_kfd<'a>(device: &GpuPci, kfd: &'a [KfdNode]) -> Option<&'a KfdNode> {
    let location = pci_location(&device.path);
    kfd.iter().find(|node| {
        node.simd_count > 0
            && node.device_id == device.device
            && node
                .location
                .is_none_or(|loc| location.is_none_or(|pci| loc == pci))
    })
}

fn pci_location(path: &Path) -> Option<u32> {
    let name = path.file_name()?.to_str()?;
    // 0000:03:00.0
    let rest = name.split_once(':')?.1;
    let (bus, devfn) = rest.split_once(':')?;
    let (dev, func) = devfn.split_once('.')?;
    let bus = u32::from_str_radix(bus, 16).ok()?;
    let dev = u32::from_str_radix(dev, 16).ok()?;
    let func = u32::from_str_radix(func, 16).ok()?;
    Some((bus << 8) | (dev << 3) | func)
}

fn apu_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x1304..=0x131D => "Kaveri",
        0x9830..=0x983F => "Kabini",
        0x9850..=0x985F => "Mullins",
        0x9870..=0x9877 => "Carrizo",
        0x98E4 => "Stoney",
        0x15D8 | 0x15DD => "Raven/Picasso",
        0x15E7 | 0x1636 | 0x1638 | 0x164C => "Renoir/Lucienne",
        0x164D | 0x164F => "Cezanne/Barcelo",
        0x1681 => "Rembrandt",
        0x163F => "Van Gogh",
        0x1435 => "Mendocino",
        0x164E => "Raphael",
        0x13C0 => "Granite Ridge",
        0x15BF | 0x15C8 | 0x1900 | 0x1901 => "Phoenix/Hawk Point",
        0x150E => "Strix Point",
        0x1114 => "Krackan Point",
        0x1586 => "Strix Halo",
        _ => return None,
    })
}

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

fn format_bytes(bytes: u64) -> String {
    if bytes >= GIB && bytes.is_multiple_of(GIB) {
        format!("{} GiB", bytes / GIB)
    } else if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

fn format_gfx(version: u64) -> String {
    let major = version / 10000;
    let minor = (version / 100) % 100;
    let stepping = version % 100;
    format!("gfx{major}{minor}{stepping}")
}

fn read_trim(ctx: &Context, path: &Path) -> Option<String> {
    ctx.reader
        .read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_u64(ctx: &Context, path: &Path) -> Option<u64> {
    read_trim(ctx, path)?.parse().ok()
}

fn parse_int(value: &str) -> u64 {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        value.parse().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_apu_ids_are_integrated() {
        assert_eq!(apu_name(0x164E), Some("Raphael"));
        assert_eq!(apu_name(0x13C0), Some("Granite Ridge"));
        assert_eq!(apu_name(0x744C), None);
    }

    #[test]
    fn gfx_target_version_matches_rocm_names() {
        assert_eq!(format_gfx(110000), "gfx1100");
        assert_eq!(format_gfx(110501), "gfx1151");
        assert_eq!(format_gfx(90000), "gfx900");
    }

    #[test]
    fn npu_is_not_a_gpu() {
        let npu = GpuPci {
            path: PathBuf::from("/sys/bus/pci/devices/0000:c1:00.1"),
            vendor: ATI,
            device: 0x17f0,
            class_hi: 0x12,
            driver: Some("amdxdna".into()),
            driver_known: true,
        };
        assert!(!is_gpu(&npu));
    }

    #[test]
    fn location_id_encodes_bdf() {
        assert_eq!(
            pci_location(Path::new("/sys/bus/pci/devices/0000:03:00.0")),
            Some(0x300)
        );
    }
}
