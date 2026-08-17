//! Linux sysfs, procfs, and device-node runtime-state probe.

use std::io;
use std::path::Path;

use crate::model::Status;
use crate::probes::{finding_detail, Context, Findings, Probe, ProbeResult};

const SRC: &str = "linux-sysfs";
const FEATURES: &[&str] = &[
    "smt",
    "kvm",
    "tpm",
    "amd_pstate",
    "cpb",
    "cpuidle",
    "energy",
    "hwmon",
    "resctrl",
    "l3_cat",
    "l3_monitoring",
    "mba",
    "ipmi",
    "bluetooth",
];

pub struct SysfsProbe;

impl Probe for SysfsProbe {
    fn name(&self) -> &'static str {
        SRC
    }
    fn feature_ids(&self) -> Vec<&'static str> {
        let mut ids = FEATURES.to_vec();
        ids.extend_from_slice(crate::probes::telemetry::FEATURES);
        ids.extend_from_slice(crate::probes::spd::FEATURES);
        ids
    }

    fn detect(&self, ctx: &Context) -> ProbeResult {
        let mut out = Vec::new();
        detect_smt(ctx, &mut out);
        detect_kvm(ctx, &mut out);
        detect_tpm(ctx, &mut out);
        detect_pstate(ctx, &mut out);
        detect_idle(ctx, &mut out);
        detect_energy(ctx, &mut out);
        detect_hwmon(ctx, &mut out);
        detect_resctrl(ctx, &mut out);
        detect_nodes(ctx, &mut out);
        out.extend(crate::probes::telemetry::findings(ctx));
        out.extend(crate::probes::spd::findings(ctx));
        Ok(out)
    }
}

fn read_trim(ctx: &Context, path: &str) -> io::Result<String> {
    ctx.reader
        .read_to_string(Path::new(path))
        .map(|s| s.trim().to_string())
}

fn path_state(ctx: &Context, path: &str) -> Result<bool, io::Error> {
    match ctx.reader.metadata(Path::new(path)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn detect_smt(ctx: &Context, out: &mut Findings) {
    let path = "/sys/devices/system/cpu/smt/active";
    let (status, detail) = match read_trim(ctx, path) {
        Ok(v) if v == "1" => (Status::Enabled, "smt/active=1".into()),
        Ok(v) if v == "0" => (Status::Disabled, "smt/active=0".into()),
        Ok(v) => (Status::Unknown, format!("malformed smt/active={v:?}")),
        Err(e) => (Status::Unknown, format!("cannot inspect smt/active: {e}")),
    };
    out.push(finding_detail(SRC, "smt", status, detail));
}

fn detect_kvm(ctx: &Context, out: &mut Findings) {
    let path = Path::new("/dev/kvm");
    let det = match ctx.reader.metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            finding_detail(SRC, "kvm", Status::Absent, "/dev/kvm absent")
        }
        Err(e) => finding_detail(
            SRC,
            "kvm",
            Status::Unknown,
            format!("cannot inspect /dev/kvm: {e}"),
        ),
        Ok(_) => match ctx.reader.open_device(path, true) {
            Ok(()) => finding_detail(SRC, "kvm", Status::Enabled, "/dev/kvm openable"),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => finding_detail(
                SRC,
                "kvm",
                Status::Present,
                "/dev/kvm present but not permitted",
            ),
            Err(e) => finding_detail(
                SRC,
                "kvm",
                Status::Unknown,
                format!("/dev/kvm open failed: {e}"),
            ),
        },
    };
    out.push(det);
}

fn detect_tpm(ctx: &Context, out: &mut Findings) {
    let states = ["/sys/class/tpm/tpm0", "/dev/tpm0"].map(|p| path_state(ctx, p));
    let (status, detail) = if states.iter().any(|s| matches!(s, Ok(true))) {
        (Status::Present, "tpm0 device present".to_string())
    } else if states.iter().all(|s| matches!(s, Ok(false))) {
        (Status::Absent, "no tpm0 device".to_string())
    } else {
        (
            Status::Unknown,
            "cannot fully inspect TPM interfaces".to_string(),
        )
    };
    out.push(finding_detail(SRC, "tpm", status, detail));
}

fn detect_pstate(ctx: &Context, out: &mut Findings) {
    let driver_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver";
    match read_trim(ctx, driver_path) {
        Ok(driver) => {
            let governor =
                read_trim(ctx, "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").ok();
            let detail = governor.map_or_else(
                || format!("driver={driver}"),
                |g| format!("driver={driver}, governor={g}"),
            );
            out.push(finding_detail(
                SRC,
                "amd_pstate",
                if driver.starts_with("amd-pstate") || driver == "amd_pstate" {
                    Status::Enabled
                } else {
                    Status::Absent
                },
                detail,
            ));
        }
        Err(e) => out.push(finding_detail(
            SRC,
            "amd_pstate",
            Status::Unknown,
            format!("cannot inspect cpufreq driver: {e}"),
        )),
    }

    match read_trim(ctx, "/sys/devices/system/cpu/cpufreq/boost") {
        Ok(v) if v == "1" => out.push(finding_detail(
            SRC,
            "cpb",
            Status::Enabled,
            "cpufreq/boost=1",
        )),
        Ok(v) if v == "0" => out.push(finding_detail(
            SRC,
            "cpb",
            Status::Disabled,
            "cpufreq/boost=0",
        )),
        Ok(v) => out.push(finding_detail(
            SRC,
            "cpb",
            Status::Unknown,
            format!("malformed cpufreq/boost={v:?}"),
        )),
        Err(e) => out.push(finding_detail(
            SRC,
            "cpb",
            Status::Unknown,
            format!("cannot inspect boost state: {e}"),
        )),
    }
}

fn detect_idle(ctx: &Context, out: &mut Findings) {
    let driver = match read_trim(ctx, "/sys/devices/system/cpu/cpuidle/current_driver") {
        Ok(driver) => driver,
        Err(e) => {
            out.push(finding_detail(
                SRC,
                "cpuidle",
                Status::Unknown,
                format!("cannot inspect cpuidle: {e}"),
            ));
            return;
        }
    };
    let mut states = Vec::new();
    for i in 0..16 {
        match read_trim(
            ctx,
            &format!("/sys/devices/system/cpu/cpu0/cpuidle/state{i}/name"),
        ) {
            Ok(name) => states.push(name),
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(_) => {
                out.push(finding_detail(
                    SRC,
                    "cpuidle",
                    Status::Unknown,
                    "cpuidle state enumeration incomplete",
                ));
                return;
            }
        }
    }
    out.push(finding_detail(
        SRC,
        "cpuidle",
        if driver.is_empty() {
            Status::Disabled
        } else {
            Status::Enabled
        },
        format!("driver={driver}, states: {}", states.join(" ")),
    ));
}

fn detect_energy(ctx: &Context, out: &mut Findings) {
    let root = Path::new("/sys/class/powercap");
    let entries = match ctx.reader.read_dir(root) {
        Ok(entries) => entries,
        Err(e) => {
            out.push(finding_detail(
                SRC,
                "energy",
                Status::Unknown,
                format!("cannot inspect powercap: {e}"),
            ));
            return;
        }
    };
    let mut domains = Vec::new();
    let mut complete = true;
    for entry in entries {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        if !entry.file_name.starts_with("amd-rapl:") && !entry.file_name.starts_with("amd_energy") {
            continue;
        }
        match ctx.reader.read_to_string(&entry.path.join("name")) {
            Ok(name) => domains.push(name.trim().to_string()),
            Err(_) => complete = false,
        }
    }
    let (status, detail) = if !complete {
        (
            Status::Unknown,
            "powercap enumeration incomplete".to_string(),
        )
    } else if domains.is_empty() {
        (Status::Absent, "no AMD powercap energy domains".to_string())
    } else {
        (Status::Enabled, format!("domains: {}", domains.join(", ")))
    };
    out.push(finding_detail(SRC, "energy", status, detail));
}

fn detect_hwmon(ctx: &Context, out: &mut Findings) {
    let entries = match ctx.reader.read_dir(Path::new("/sys/class/hwmon")) {
        Ok(entries) => entries,
        Err(e) => {
            out.push(finding_detail(
                SRC,
                "hwmon",
                Status::Unknown,
                format!("cannot inspect hwmon: {e}"),
            ));
            return;
        }
    };
    let mut names = Vec::new();
    let mut complete = true;
    for entry in entries {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        match ctx.reader.read_to_string(&entry.path.join("name")) {
            Ok(name) if matches!(name.trim(), "k10temp" | "zenpower" | "amd_energy") => {
                names.push(name.trim().to_string())
            }
            Ok(_) => {}
            Err(_) => complete = false,
        }
    }
    let (status, detail) = if !names.is_empty() {
        (Status::Enabled, format!("sensors: {}", names.join(", ")))
    } else if complete {
        (Status::Absent, "no AMD CPU hwmon driver".to_string())
    } else {
        (Status::Unknown, "hwmon enumeration incomplete".to_string())
    };
    out.push(finding_detail(SRC, "hwmon", status, detail));
}

fn detect_resctrl(ctx: &Context, out: &mut Findings) {
    let info = path_state(ctx, "/sys/fs/resctrl/info");
    let root = path_state(ctx, "/sys/fs/resctrl");
    let root_present = matches!(root, Ok(true));
    let (status, detail) = match (info, &root) {
        (Ok(true), _) => (Status::Enabled, "mounted at /sys/fs/resctrl"),
        (Ok(false), Ok(true)) => (Status::Present, "present but not mounted"),
        (Ok(false), Ok(false)) => (Status::Absent, "no /sys/fs/resctrl"),
        _ => (Status::Unknown, "cannot inspect resctrl"),
    };
    out.push(finding_detail(SRC, "resctrl", status, detail));
    for (id, path) in [
        ("l3_cat", "/sys/fs/resctrl/info/L3"),
        ("l3_monitoring", "/sys/fs/resctrl/info/L3_MON"),
        ("mba", "/sys/fs/resctrl/info/MB"),
    ] {
        let (status, detail) = match path_state(ctx, path) {
            Ok(true) => (Status::Enabled, format!("{path} available")),
            Ok(false) if root_present => (Status::Absent, format!("{path} absent")),
            Ok(false) => (Status::Unknown, "resctrl is not mounted".to_string()),
            Err(e) => (Status::Unknown, format!("cannot inspect {path}: {e}")),
        };
        out.push(finding_detail(SRC, id, status, detail));
    }
}

fn detect_nodes(ctx: &Context, out: &mut Findings) {
    let ipmi = ["/dev/ipmi0", "/dev/ipmi/0"].map(|p| path_state(ctx, p));
    let (status, detail) = if ipmi.iter().any(|s| matches!(s, Ok(true))) {
        (Status::Enabled, "IPMI device present")
    } else if ipmi.iter().all(|s| matches!(s, Ok(false))) {
        (Status::Absent, "no IPMI device")
    } else {
        (Status::Unknown, "cannot fully inspect IPMI devices")
    };
    out.push(finding_detail(SRC, "ipmi", status, detail));

    match ctx.reader.read_dir(Path::new("/sys/class/bluetooth")) {
        Ok(entries) if entries.iter().any(Result::is_err) => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Unknown,
            "bluetooth enumeration incomplete",
        )),
        Ok(entries) if entries.is_empty() => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Absent,
            "no bluetooth hci",
        )),
        Ok(_) => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Enabled,
            "hci device present",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Absent,
            "no bluetooth class",
        )),
        Err(e) => out.push(finding_detail(
            SRC,
            "bluetooth",
            Status::Unknown,
            format!("cannot inspect bluetooth: {e}"),
        )),
    }
}
