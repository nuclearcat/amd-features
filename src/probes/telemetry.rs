//! CPU frequency, package power, 3D V-Cache, and fabric/memory-clock telemetry.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::model::Status;
use crate::probes::firmware;
use crate::probes::{finding_detail, Context, Findings};

const SRC: &str = "linux-sysfs";
pub(crate) const FEATURES: &[&str] = &["cpu_freq", "package_power", "vcache", "fabric"];

pub(crate) fn findings(ctx: &Context) -> Findings {
    vec![cpu_freq(ctx), package_power(ctx), vcache(ctx), fabric(ctx)]
}

fn cpu_freq(ctx: &Context) -> (&'static str, crate::model::Detection) {
    let cpus = match cpu_indexes(ctx) {
        Ok(cpus) => cpus,
        Err(reason) => {
            return finding_detail(SRC, "cpu_freq", Status::Unknown, reason);
        }
    };
    if cpus.is_empty() {
        return finding_detail(
            SRC,
            "cpu_freq",
            Status::Unknown,
            "no logical CPU sysfs nodes",
        );
    }
    let mut mins = Vec::new();
    let mut maxs = Vec::new();
    let mut boosts = Vec::new();
    let mut curs = Vec::new();
    let mut missing = 0usize;
    let mut present = 0usize;
    for cpu in &cpus {
        let base = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq");
        let min = read_khz(ctx, &format!("{base}/cpuinfo_min_freq"));
        let max = read_khz(ctx, &format!("{base}/cpuinfo_max_freq"))
            .or_else(|| read_khz(ctx, &format!("{base}/amd_pstate_max_freq")));
        let boost = read_khz(ctx, &format!("{base}/amd_pstate_max_freq"));
        let cur = read_khz(ctx, &format!("{base}/scaling_cur_freq"))
            .or_else(|| read_khz(ctx, &format!("{base}/cpuinfo_cur_freq")));
        if min.is_none() && max.is_none() && cur.is_none() {
            missing += 1;
            continue;
        }
        present += 1;
        if let Some(v) = min {
            mins.push(v);
        }
        if let Some(v) = max {
            maxs.push(v);
        }
        if let Some(v) = boost {
            if Some(v) != max {
                boosts.push(v);
            }
        }
        if let Some(v) = cur {
            curs.push(v);
        }
    }
    if present == 0 {
        return finding_detail(
            SRC,
            "cpu_freq",
            if missing == cpus.len() {
                Status::Unknown
            } else {
                Status::Absent
            },
            "no cpufreq interface on logical CPUs",
        );
    }
    let mut parts = Vec::new();
    if let Some(range) = mhz_range(&maxs) {
        let label = if maxs.iter().min() != maxs.iter().max() {
            "boost (asymmetric CCDs)"
        } else {
            "boost"
        };
        parts.push(format!("{label} {range}"));
    }
    if let Some(range) = mhz_range(&boosts) {
        parts.push(format!("amd_pstate max {range}"));
    }
    if let Some(range) = mhz_range(&mins) {
        parts.push(format!("min {range}"));
    }
    if let Some(cur) = curs.iter().copied().max() {
        parts.push(format!("current {}", format_mhz(cur)));
    }
    if let Some(boost) = read_trim(ctx, "/sys/devices/system/cpu/cpufreq/boost") {
        parts.push(format!(
            "cpufreq boost={}",
            match boost.as_str() {
                "1" => "on",
                "0" => "off",
                other => other,
            }
        ));
    }
    finding_detail(SRC, "cpu_freq", Status::Present, parts.join(", "))
}

fn package_power(ctx: &Context) -> (&'static str, crate::model::Detection) {
    let mut parts = Vec::new();
    let mut complete = true;
    match ctx.reader.read_dir(Path::new("/sys/class/powercap")) {
        Ok(entries) => {
            for entry in entries {
                let Ok(entry) = entry else {
                    complete = false;
                    continue;
                };
                let name =
                    read_trim(ctx, &entry.path.join("name").to_string_lossy()).unwrap_or_default();
                if !is_package_rapl(&entry.file_name, &name) {
                    continue;
                }
                let mut constraints = Vec::new();
                for i in 0..4 {
                    let label = read_trim(
                        ctx,
                        &entry
                            .path
                            .join(format!("constraint_{i}_name"))
                            .to_string_lossy(),
                    );
                    let limit = read_uw(
                        ctx,
                        &entry
                            .path
                            .join(format!("constraint_{i}_power_limit_uw"))
                            .to_string_lossy(),
                    );
                    let max = read_uw(
                        ctx,
                        &entry
                            .path
                            .join(format!("constraint_{i}_max_power_uw"))
                            .to_string_lossy(),
                    );
                    match (label, limit, max) {
                        (Some(label), Some(limit), max) => {
                            let mut text =
                                format!("{} {}", rapl_label(&label), format_watts(limit));
                            if let Some(max) = max {
                                text.push_str(&format!(" (max {})", format_watts(max)));
                            }
                            constraints.push(text);
                        }
                        (None, None, None) => break,
                        _ => complete = false,
                    }
                }
                if !constraints.is_empty() {
                    parts.push(format!(
                        "{}: {}",
                        if name.is_empty() {
                            entry.file_name.as_str()
                        } else {
                            name.as_str()
                        },
                        constraints.join(", ")
                    ));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => complete = false,
    }

    for (label, watts) in hwmon_power(ctx, &mut complete) {
        parts.push(format!("hwmon {label} {}", format_watts(watts)));
    }

    if parts.is_empty() {
        finding_detail(
            SRC,
            "package_power",
            Status::Unknown,
            if complete {
                "no RAPL power-limit or AMD hwmon power channels"
            } else {
                "power interface enumeration incomplete"
            },
        )
    } else {
        finding_detail(SRC, "package_power", Status::Present, parts.join("; "))
    }
}

fn vcache(ctx: &Context) -> (&'static str, crate::model::Detection) {
    let brand = cpu_brand(ctx).unwrap_or_default();
    let brand_hit = brand.to_ascii_uppercase().contains("X3D")
        || brand.to_ascii_uppercase().contains("V-CACHE")
        || brand.to_ascii_uppercase().contains("3D V-CACHE");
    let mode = x3d_mode(ctx);
    let caches = match l3_caches(ctx) {
        Ok(caches) => caches,
        Err(reason) => {
            if brand_hit || mode.is_some() {
                let mut parts = Vec::new();
                if brand_hit {
                    parts.push("product name indicates 3D V-Cache".into());
                }
                if let Some(mode) = mode {
                    parts.push(format!("amd_x3d_vcache mode={mode}"));
                }
                return finding_detail(SRC, "vcache", Status::Present, parts.join("; "));
            }
            return finding_detail(SRC, "vcache", Status::Unknown, reason);
        }
    };
    let sizes: BTreeSet<_> = caches.iter().map(|c| c.kib).collect();
    let stacked = caches.iter().any(|c| c.kib >= 96 * 1024);
    let mixed = sizes.contains(&(32 * 1024)) && stacked;
    if !brand_hit && mode.is_none() && !stacked {
        let detail = if caches.is_empty() {
            "no L3 cache sysfs nodes".into()
        } else {
            format!("L3 {}; no 3D V-Cache topology", format_l3(&caches))
        };
        return finding_detail(
            SRC,
            "vcache",
            if caches.is_empty() {
                Status::Unknown
            } else {
                Status::Absent
            },
            detail,
        );
    }
    let mut parts = vec![format!("L3 {}", format_l3(&caches))];
    if mixed {
        parts.push("asymmetric CCDs (96 MiB V-Cache + 32 MiB)".into());
    } else if stacked {
        parts.push("96 MiB-class L3 indicates stacked V-Cache".into());
    }
    if brand_hit {
        parts.push("product name X3D/V-Cache".into());
    }
    if let Some(mode) = mode {
        parts.push(format!("amd_x3d_vcache mode={mode}"));
    }
    finding_detail(SRC, "vcache", Status::Enabled, parts.join("; "))
}

fn fabric(ctx: &Context) -> (&'static str, crate::model::Detection) {
    let mut parts = Vec::new();
    let mut complete = true;
    for (label, mhz) in hwmon_freq(ctx, &mut complete) {
        parts.push(format!("{label} {mhz} MHz"));
    }
    let rates = firmware::dimm_data_rates(ctx);
    if !rates.is_empty() {
        let min = *rates.iter().min().unwrap();
        let max = *rates.iter().max().unwrap();
        parts.push(if min == max {
            format!("memory data rate {max} MT/s (SMBIOS)")
        } else {
            format!("memory data rate {min}-{max} MT/s (SMBIOS)")
        });
    }
    if parts.is_empty() {
        finding_detail(
            SRC,
            "fabric",
            Status::Unknown,
            if complete {
                "no SMU/hwmon fabric clocks and no SMBIOS memory speed"
            } else {
                "fabric/memory clock enumeration incomplete"
            },
        )
    } else if parts.iter().any(|p| p.contains("MHz")) {
        finding_detail(SRC, "fabric", Status::Present, parts.join("; "))
    } else {
        finding_detail(
            SRC,
            "fabric",
            Status::Present,
            format!("{}; FCLK/UCLK not exposed by this kernel", parts.join("; ")),
        )
    }
}

struct L3 {
    kib: u32,
    cpus: String,
}

fn l3_caches(ctx: &Context) -> Result<Vec<L3>, String> {
    let cpus = cpu_indexes(ctx)?;
    let mut by_share: BTreeMap<String, u32> = BTreeMap::new();
    let mut complete = true;
    for cpu in cpus {
        let cache = format!("/sys/devices/system/cpu/cpu{cpu}/cache");
        let entries = match ctx.reader.read_dir(Path::new(&cache)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        for entry in entries.into_iter().flatten() {
            if !entry.file_name.starts_with("index") {
                continue;
            }
            let level = read_trim(ctx, &entry.path.join("level").to_string_lossy());
            if level.as_deref() != Some("3") {
                continue;
            }
            let Some(size) = read_trim(ctx, &entry.path.join("size").to_string_lossy())
                .and_then(|s| parse_cache_kib(&s))
            else {
                complete = false;
                continue;
            };
            let share = read_trim(ctx, &entry.path.join("shared_cpu_list").to_string_lossy())
                .unwrap_or_else(|| format!("{cpu}"));
            by_share.entry(share).or_insert(size);
        }
    }
    if by_share.is_empty() {
        return Err(if complete {
            "no L3 cache sysfs nodes".into()
        } else {
            "L3 cache enumeration incomplete".into()
        });
    }
    Ok(by_share
        .into_iter()
        .map(|(cpus, kib)| L3 { kib, cpus })
        .collect())
}

fn x3d_mode(ctx: &Context) -> Option<String> {
    let roots = [
        "/sys/bus/platform/drivers/amd_x3d_vcache",
        "/sys/devices/platform",
    ];
    for root in roots {
        let Ok(entries) = ctx.reader.read_dir(Path::new(root)) else {
            continue;
        };
        for entry in entries.into_iter().flatten() {
            if let Some(mode) = read_trim(ctx, &entry.path.join("amd_x3d_mode").to_string_lossy()) {
                return Some(mode);
            }
        }
    }
    None
}

fn hwmon_power(ctx: &Context, complete: &mut bool) -> Vec<(String, u64)> {
    hwmon_channels(ctx, complete, "power", Some, is_power_label)
}

fn hwmon_freq(ctx: &Context, complete: &mut bool) -> Vec<(String, u64)> {
    hwmon_channels(
        ctx,
        complete,
        "freq",
        |raw| {
            let mhz = if raw >= 100_000 { raw / 1_000_000 } else { raw };
            (mhz > 0).then_some(mhz)
        },
        is_fabric_label,
    )
}

fn hwmon_channels(
    ctx: &Context,
    complete: &mut bool,
    prefix: &str,
    scale: fn(u64) -> Option<u64>,
    interesting: fn(&str) -> bool,
) -> Vec<(String, u64)> {
    let Ok(entries) = ctx.reader.read_dir(Path::new("/sys/class/hwmon")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            *complete = false;
            continue;
        };
        let name = read_trim(ctx, &entry.path.join("name").to_string_lossy()).unwrap_or_default();
        if !is_amd_hwmon(&name) {
            continue;
        }
        for i in 1..16 {
            let input = entry.path.join(format!("{prefix}{i}_input"));
            let Some(raw) = read_u64(ctx, &input.to_string_lossy()) else {
                if i == 1 {
                    break;
                }
                continue;
            };
            let Some(value) = scale(raw) else { continue };
            let label = read_trim(
                ctx,
                &entry
                    .path
                    .join(format!("{prefix}{i}_label"))
                    .to_string_lossy(),
            )
            .unwrap_or_else(|| format!("{name} {prefix}{i}"));
            if interesting(&label) {
                out.push((label, value));
            }
        }
    }
    out
}

fn is_amd_hwmon(name: &str) -> bool {
    matches!(
        name,
        "k10temp" | "zenpower" | "zenpower3" | "zenpower5" | "amd_energy" | "ryzen_smu"
    ) || name.starts_with("zenpower")
}

fn is_power_label(label: &str) -> bool {
    let l = label.to_ascii_uppercase();
    [
        "PPT", "TDP", "STAPM", "PACKAGE", "SOC", "TDC", "EDC", "POWER",
    ]
    .iter()
    .any(|tok| l.contains(tok))
        || l.contains("SOCKET")
}

fn is_fabric_label(label: &str) -> bool {
    let l = label.to_ascii_lowercase();
    [
        "fclk", "uclk", "mclk", "fabric", "memclk", "memory", "infinity",
    ]
    .iter()
    .any(|tok| l.contains(tok))
}

fn is_package_rapl(file: &str, name: &str) -> bool {
    let colons = file.bytes().filter(|b| *b == b':').count();
    if colons >= 2 {
        return false;
    }
    let name = name.to_ascii_lowercase();
    (file.contains("rapl") || name.contains("package")) && !name.contains("core")
}

fn rapl_label(name: &str) -> String {
    match name {
        "long_term" => "TDP/long_term".into(),
        "short_term" => "PPT/short_term".into(),
        other => other.into(),
    }
}

fn cpu_indexes(ctx: &Context) -> Result<Vec<u32>, String> {
    let entries = ctx
        .reader
        .read_dir(Path::new("/sys/devices/system/cpu"))
        .map_err(|e| format!("cannot inspect CPU sysfs: {e}"))?;
    let mut cpus = Vec::new();
    for entry in entries.into_iter().flatten() {
        let Some(rest) = entry.file_name.strip_prefix("cpu") else {
            continue;
        };
        if rest.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(cpu) = rest.parse() {
                cpus.push(cpu);
            }
        }
    }
    cpus.sort_unstable();
    Ok(cpus)
}

fn cpu_brand(ctx: &Context) -> Option<String> {
    let info = ctx.reader.read_to_string(Path::new("/proc/cpuinfo")).ok()?;
    info.lines().find_map(|line| {
        line.split_once(':')
            .and_then(|(k, v)| (k.trim() == "model name").then(|| v.trim().to_string()))
    })
}

fn format_l3(caches: &[L3]) -> String {
    caches
        .iter()
        .map(|c| format!("{} (CPUs {})", format_mib(c.kib), c.cpus))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_mib(kib: u32) -> String {
    if kib.is_multiple_of(1024) {
        format!("{} MiB", kib / 1024)
    } else {
        format!("{kib} KiB")
    }
}

fn parse_cache_kib(text: &str) -> Option<u32> {
    let text = text.trim().to_ascii_uppercase();
    if let Some(v) = text.strip_suffix('K') {
        v.parse().ok()
    } else if let Some(v) = text.strip_suffix('M') {
        v.parse::<u32>().ok().map(|m| m * 1024)
    } else {
        text.parse().ok()
    }
}

fn mhz_range(values: &[u64]) -> Option<String> {
    let min = *values.iter().min()?;
    let max = *values.iter().max()?;
    Some(if min == max {
        format_mhz(min)
    } else {
        format!("{}-{}", format_mhz(min), format_mhz(max))
    })
}

fn format_mhz(khz: u64) -> String {
    if khz.is_multiple_of(1000) {
        format!("{} MHz", khz / 1000)
    } else {
        format!("{:.1} MHz", khz as f64 / 1000.0)
    }
}

fn format_watts(uw: u64) -> String {
    let watts = uw as f64 / 1_000_000.0;
    if (watts - watts.round()).abs() < 0.05 {
        format!("{} W", watts.round() as u64)
    } else {
        format!("{watts:.1} W")
    }
}

fn read_trim(ctx: &Context, path: &str) -> Option<String> {
    ctx.reader
        .read_to_string(Path::new(path))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_khz(ctx: &Context, path: &str) -> Option<u64> {
    read_u64(ctx, path).filter(|v| *v > 0)
}

fn read_uw(ctx: &Context, path: &str) -> Option<u64> {
    read_u64(ctx, path).filter(|v| *v > 0)
}

fn read_u64(ctx: &Context, path: &str) -> Option<u64> {
    read_trim(ctx, path)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_size_parses_k_and_m() {
        assert_eq!(parse_cache_kib("32768K"), Some(32768));
        assert_eq!(parse_cache_kib("96M"), Some(96 * 1024));
    }

    #[test]
    fn rapl_names_map_to_tdp_and_ppt() {
        assert_eq!(rapl_label("long_term"), "TDP/long_term");
        assert_eq!(rapl_label("short_term"), "PPT/short_term");
    }
}
