//! Read-only runtime snapshots from documented Linux sysfs interfaces.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use crate::model::{Detection, Status};
use crate::probes::{finding_detail, Context, Findings};

const SRC: &str = "linux-sysfs";
pub(crate) const FEATURES: &[&str] = &["power_policy", "temperatures", "fan_speeds", "usb4"];

pub(crate) fn findings(ctx: &Context) -> Findings {
    let mut out = sensors(ctx);
    out.push(power_policy(ctx));
    out.push(usb4(ctx));
    out
}

// Optional attributes may legitimately be absent on older kernels or drivers.
// Access errors and malformed values must remain visible in the snapshot.
fn field(ctx: &Context, base: &Path, name: &str, errors: &mut Vec<String>) -> Option<String> {
    let path = base.join(name);
    match ctx.reader.read_to_string(&path) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        Ok(_) => {
            errors.push(format!("{}: empty value", path.display()));
            None
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            errors.push(format!("{}: {e}", path.display()));
            None
        }
    }
}

fn required(ctx: &Context, base: &Path, name: &str, errors: &mut Vec<String>) -> Option<String> {
    let before = errors.len();
    let value = field(ctx, base, name, errors);
    if value.is_none() && errors.len() == before {
        errors.push(format!("{}: not exposed", base.join(name).display()));
    }
    value
}

fn snapshot(
    id: &'static str,
    mut parts: Vec<String>,
    mut errors: Vec<String>,
    empty: &str,
) -> (&'static str, Detection) {
    let status = if !errors.is_empty() {
        Status::Unknown
    } else if parts.is_empty() {
        Status::Absent
    } else {
        Status::Present
    };
    if parts.is_empty() {
        parts.push(empty.into());
    }
    if !errors.is_empty() {
        errors.sort();
        parts.push(format!("incomplete: {}", errors.join("; ")));
    }
    finding_detail(SRC, id, status, parts.join("\n"))
}

fn numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

fn sensors(ctx: &Context) -> Findings {
    let mut readings = [Vec::new(), Vec::new()];
    let mut errors = [Vec::new(), Vec::new()];
    let root = Path::new("/sys/class/hwmon");
    match ctx.reader.read_dir(root) {
        Err(e) => {
            for errors in &mut errors {
                errors.push(format!("{}: {e}", root.display()));
            }
        }
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        for errors in &mut errors {
                            errors.push(format!("hwmon enumeration: {e}"));
                        }
                        continue;
                    }
                };
                let mut common_errors = Vec::new();
                let name = required(ctx, &entry.path, "name", &mut common_errors)
                    .unwrap_or_else(|| "unknown driver".into());
                let channels = match ctx.reader.read_dir(&entry.path) {
                    Ok(channels) => channels,
                    Err(e) => {
                        common_errors.push(format!("{}: {e}", entry.path.display()));
                        Vec::new()
                    }
                };
                for channel in channels {
                    let channel = match channel {
                        Ok(channel) => channel,
                        Err(e) => {
                            common_errors.push(format!("{}: {e}", entry.path.display()));
                            continue;
                        }
                    };
                    let Some(stem) = channel.file_name.strip_suffix("_input") else {
                        continue;
                    };
                    let index = if numbered(stem, "temp") {
                        0
                    } else if numbered(stem, "fan") {
                        1
                    } else {
                        continue;
                    };
                    let errors = &mut errors[index];
                    let label = field(ctx, &entry.path, &format!("{stem}_label"), errors)
                        .unwrap_or_else(|| stem.into());
                    let identity = format!("{name}/{} {label} ({stem})", entry.file_name);
                    let enable = field(ctx, &entry.path, &format!("{stem}_enable"), errors);
                    if enable.as_deref() == Some("0") {
                        readings[index].push(format!("{identity}: disabled"));
                        continue;
                    }
                    if enable.as_deref().is_some_and(|s| s != "1") {
                        errors.push(format!("{identity}: malformed enable={enable:?}"));
                        continue;
                    }
                    let fault = field(ctx, &entry.path, &format!("{stem}_fault"), errors);
                    if fault.as_deref().is_some_and(|s| s != "0") {
                        errors.push(format!("{identity}: fault={}", fault.unwrap()));
                        continue;
                    }
                    let Some(raw) = required(ctx, &entry.path, &channel.file_name, errors) else {
                        continue;
                    };
                    match raw.parse::<i64>() {
                        Ok(value) if index == 0 => readings[index]
                            .push(format!("{identity}: {:.3} °C", value as f64 / 1000.0)),
                        Ok(value) if value >= 0 => {
                            readings[index].push(format!("{identity}: {value} RPM"))
                        }
                        _ => errors.push(format!(
                            "{}: malformed reading {raw:?}",
                            channel.path.display()
                        )),
                    }
                }
                for errors in &mut errors {
                    errors.extend(common_errors.iter().cloned());
                }
            }
        }
    }
    let [mut temps, mut fans] = readings;
    temps.sort();
    fans.sort();
    let [temp_errors, fan_errors] = errors;
    vec![
        snapshot(
            "temperatures",
            temps,
            temp_errors,
            "no hwmon temperature input channels exposed",
        ),
        snapshot(
            "fan_speeds",
            fans,
            fan_errors,
            "no hwmon fan input channels exposed",
        ),
    ]
}

fn power_policy(ctx: &Context) -> (&'static str, Detection) {
    let mut parts = Vec::new();
    let mut errors = Vec::new();
    let amd = Path::new("/sys/devices/system/cpu/amd_pstate");
    for (name, allowed) in [
        ("status", &["active", "passive", "guided", "disable"][..]),
        ("prefcore", &["enabled", "disabled"][..]),
    ] {
        if let Some(value) = field(ctx, amd, name, &mut errors) {
            if allowed.contains(&value.as_str()) {
                parts.push(format!("amd_pstate {name}={value}"));
            } else {
                errors.push(format!("amd_pstate {name}: unrecognized {value:?}"));
            }
        }
    }
    let root = Path::new("/sys/devices/system/cpu/cpufreq");
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    match ctx.reader.read_dir(root) {
        Err(e) => errors.push(format!("{}: {e}", root.display())),
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        errors.push(format!("cpufreq enumeration: {e}"));
                        continue;
                    }
                };
                if !numbered(&entry.file_name, "policy") {
                    continue;
                }
                let mut values = Vec::new();
                for (file, label) in [
                    ("scaling_driver", "driver"),
                    ("scaling_governor", "governor"),
                ] {
                    if let Some(value) = required(ctx, &entry.path, file, &mut errors) {
                        values.push(format!("{label}={value}"));
                    }
                }
                let epp = field(
                    ctx,
                    &entry.path,
                    "energy_performance_preference",
                    &mut errors,
                );
                values.push(format!("EPP={}", epp.as_deref().unwrap_or("not exposed")));
                for (file, label) in [
                    ("energy_performance_available_preferences", "available EPP"),
                    ("scaling_available_governors", "available governors"),
                ] {
                    if let Some(value) = field(ctx, &entry.path, file, &mut errors) {
                        values.push(format!("{label}=[{value}]"));
                    }
                }
                let mut limits = Vec::new();
                for file in ["scaling_min_freq", "scaling_max_freq"] {
                    if let Some(raw) = required(ctx, &entry.path, file, &mut errors) {
                        match raw.parse::<u64>() {
                            Ok(v) if v > 0 => limits.push(v),
                            _ => errors.push(format!(
                                "{}: malformed {raw:?}",
                                entry.path.join(file).display()
                            )),
                        }
                    }
                }
                if limits.len() == 2 {
                    if limits[0] > limits[1] {
                        errors.push(format!(
                            "{}: minimum frequency exceeds maximum",
                            entry.file_name
                        ));
                    } else {
                        values.push(format!(
                            "limits={:.3}-{:.3} MHz",
                            limits[0] as f64 / 1000.0,
                            limits[1] as f64 / 1000.0
                        ));
                    }
                }
                if let Some(boost) = field(ctx, &entry.path, "boost", &mut errors) {
                    match boost.as_str() {
                        "0" => values.push("boost=off".into()),
                        "1" => values.push("boost=on".into()),
                        _ => errors.push(format!("{}: malformed boost={boost:?}", entry.file_name)),
                    }
                }
                groups
                    .entry(values.join(", "))
                    .or_default()
                    .push(entry.file_name);
            }
        }
    }
    for (values, mut policies) in groups {
        policies.sort_by_key(|s| s[6..].parse::<u32>().unwrap_or(u32::MAX));
        parts.push(format!("{}: {values}", policies.join(",")));
    }
    snapshot("power_policy", parts, errors, "no cpufreq policies exposed")
}

fn usb4(ctx: &Context) -> (&'static str, Detection) {
    let root = Path::new("/sys/bus/thunderbolt/devices");
    let mut parts = Vec::new();
    let mut errors = Vec::new();
    let mut found = false;
    match ctx.reader.read_dir(root) {
        Err(e) => errors.push(format!("{}: {e}", root.display())),
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        errors.push(format!("Thunderbolt enumeration: {e}"));
                        continue;
                    }
                };
                if numbered(&entry.file_name, "domain") {
                    let mut values = Vec::new();
                    for file in ["security", "iommu_dma_protection"] {
                        if let Some(value) = field(ctx, &entry.path, file, &mut errors) {
                            values.push(format!("{file}={value}"));
                        }
                    }
                    if !values.is_empty() {
                        parts.push(format!("{}: {}", entry.file_name, values.join(", ")));
                    }
                    continue;
                }
                // Router names are domain-route; exclude ports, retimers and services.
                let Some((domain, route)) = entry.file_name.split_once('-') else {
                    continue;
                };
                if domain.is_empty()
                    || route.is_empty()
                    || !domain.bytes().all(|b| b.is_ascii_digit())
                    || !route.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    continue;
                }
                let Some(generation) = required(ctx, &entry.path, "generation", &mut errors) else {
                    continue;
                };
                match generation.as_str() {
                    "1" | "2" | "3" => continue,
                    "4" => found = true,
                    _ => {
                        errors.push(format!(
                            "{}: unrecognized generation={generation:?}",
                            entry.file_name
                        ));
                        continue;
                    }
                }
                let name = field(ctx, &entry.path, "device_name", &mut errors)
                    .unwrap_or_else(|| "unnamed router".into());
                let mut values = vec![format!(
                    "{} {name}: USB4 (generation=4, {} router)",
                    entry.file_name,
                    if route == "0" { "host" } else { "device" }
                )];
                for file in ["authorized", "rx_speed", "tx_speed", "rx_lanes", "tx_lanes"] {
                    if let Some(value) = field(ctx, &entry.path, file, &mut errors) {
                        let suffix = if file.ends_with("_speed") {
                            " per lane"
                        } else {
                            ""
                        };
                        values.push(format!("{file}={value}{suffix}"));
                    }
                }
                parts.push(values.join(", "));
            }
        }
    }
    parts.sort();
    if !found {
        parts.insert(0, "no USB4 routers enumerated".into());
    }
    let mut result = snapshot("usb4", parts, errors, "no USB4 routers enumerated");
    if result.1.status != Status::Unknown {
        result.1.status = if found {
            Status::Enabled
        } else {
            Status::Absent
        };
    }
    result
}
