//! Per-logical-CPU AMD CPUID probe.

use std::collections::HashSet;
use std::path::Path;

use crate::cpu_db::{self, CpuModelInfo};
use crate::model::{Detection, Status};
use crate::probes::{unavailable, Context, Probe, ProbeResult};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Identity {
    pub vendor: String,
    pub brand: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_info: Option<CpuModelInfo>,
    pub logical_cpus: usize,
    /// Kept in the stable JSON schema; AMD heterogeneous core type is not exposed by
    /// the Intel-specific CPUID.1A encoding.
    pub hybrid: bool,
    pub p_cores: usize,
    pub e_cores: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub microcode: Option<String>,
}

pub struct CpuidProbe;

const FEATURES: &[&str] = &[
    "abm",
    "adx",
    "aes",
    "arch_perfmon",
    "avx",
    "avx2",
    "avx_vnni",
    "avx512bf16",
    "avx512bitalg",
    "avx512bw",
    "avx512cd",
    "avx512dq",
    "avx512f",
    "avx512fp16",
    "avx512ifma",
    "avx512vbmi",
    "avx512vbmi2",
    "avic",
    "avx512vl",
    "avx512vnni",
    "avx512vpopcntdq",
    "bmi1",
    "bmi2",
    "btc_no",
    "clflushopt",
    "clwb",
    "clzero",
    "cmpxchg16b",
    "cpb",
    "cppc",
    "decodeassists",
    "f16c",
    "flushbyasid",
    "fma",
    "fma4",
    "fsgsbase",
    "gfni",
    "htt",
    "hypervisor",
    "ibpb",
    "ibrs",
    "ibs",
    "invariant_tsc",
    "lbrv",
    "movdir64b",
    "movdiri",
    "mwaitx",
    "npt",
    "nrip_save",
    "nx",
    "ospke",
    "pausefilter",
    "pclmulqdq",
    "perfctr_core",
    "perfctr_nb",
    "perfmon_v2",
    "pku",
    "popcnt",
    "psfd",
    "rdpid",
    "rdpru",
    "rdrand",
    "rdseed",
    "rdtscp",
    "serialize",
    "sev",
    "sev_es",
    "sev_snp",
    "sha",
    "smap",
    "sme",
    "smep",
    "sse",
    "sse2",
    "sse3",
    "sse4_1",
    "sse4_2",
    "sse4a",
    "ssbd",
    "ssb_no",
    "ssse3",
    "stibp",
    "svm",
    "svm_lock",
    "tbm",
    "topoext",
    "tsc_scale",
    "umip",
    "v_vmsave_vmload",
    "vaes",
    "vgif",
    "virt_ssbd",
    "vmcb_clean",
    "vmpl",
    "vpclmulqdq",
    "vte",
    "wbnoinvd",
    "x2apic",
    "xop",
    "xsave",
    "xsavec",
    "xsaveopt",
    "xsaves",
];

impl Probe for CpuidProbe {
    fn name(&self) -> &'static str {
        "cpuid"
    }
    fn feature_ids(&self) -> Vec<&'static str> {
        FEATURES.to_vec()
    }
    fn detect(&self, ctx: &Context) -> ProbeResult {
        let scan = run_scan(ctx);
        if scan.detections.is_empty() {
            Ok(unavailable(
                self.name(),
                FEATURES,
                "no eligible logical CPU could be scanned",
            ))
        } else {
            Ok(scan.detections)
        }
    }
}

pub fn identity() -> Option<Identity> {
    identity_with(&Context::detect())
}
pub fn identity_with(ctx: &Context) -> Option<Identity> {
    run_scan(ctx).identity
}

struct Scan {
    identity: Option<Identity>,
    detections: Vec<(&'static str, Detection)>,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
struct CoreScan {
    logical_cpu: u32,
    physical_key: Option<u64>,
    feats: Vec<(&'static str, bool, &'static str)>,
    ident: CoreIdent,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
struct CoreIdent {
    vendor: String,
    brand: String,
    family: u32,
    model: u32,
    stepping: u32,
}

#[cfg(target_arch = "x86_64")]
mod raw {
    use core::arch::x86_64::__cpuid_count;
    pub fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
        let r = __cpuid_count(leaf, subleaf);
        (r.eax, r.ebx, r.ecx, r.edx)
    }
    pub fn bit(value: u32, bit: u32) -> bool {
        ((value >> bit) & 1) != 0
    }
}

#[cfg(target_arch = "x86_64")]
fn run_scan(ctx: &Context) -> Scan {
    let cores: Vec<_> = eligible_cpus(ctx)
        .into_iter()
        .filter_map(|cpu| scan_pinned(cpu, ctx.clone()))
        .collect();
    let Some(first) = cores.first() else {
        return Scan {
            identity: None,
            detections: Vec::new(),
        };
    };
    let identity = build_identity(&cores, ctx);
    let amd = matches!(first.ident.vendor.as_str(), "AuthenticAMD" | "HygonGenuine");
    let detections = if amd {
        aggregate(&cores)
    } else {
        unavailable(
            "cpuid",
            FEATURES,
            format!("CPU vendor is {}, not AMD", first.ident.vendor),
        )
    };
    Scan {
        identity: Some(identity),
        detections,
    }
}

#[cfg(target_arch = "x86_64")]
fn scan_pinned(cpu: u32, ctx: Context) -> Option<CoreScan> {
    std::thread::Builder::new()
        .name(format!("cpuid-scan-{cpu}"))
        .spawn(move || pin_to(cpu).then(|| scan_core(cpu, &ctx)))
        .ok()?
        .join()
        .ok()?
}

#[cfg(target_arch = "x86_64")]
fn pin_to(cpu: u32) -> bool {
    let word_bits = usize::BITS as usize;
    let mut mask = vec![0usize; cpu as usize / word_bits + 1];
    mask[cpu as usize / word_bits] |= 1usize << (cpu as usize % word_bits);
    // SAFETY: mask points to its fully initialized allocation for the supplied size.
    unsafe {
        libc::sched_setaffinity(
            0,
            std::mem::size_of_val(mask.as_slice()),
            mask.as_ptr().cast(),
        ) == 0
    }
}

#[cfg(target_arch = "x86_64")]
fn scan_core(logical_cpu: u32, ctx: &Context) -> CoreScan {
    use raw::{bit, cpuid};
    let (max_basic, ebx0, ecx0, edx0) = cpuid(0, 0);
    let vendor = [ebx0, edx0, ecx0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .map(char::from)
        .collect::<String>();
    let max_ext = cpuid(0x8000_0000, 0).0;
    let (_, _, l1c, l1d) = cpuid(1, 0);
    let mut feats = Vec::new();
    let mut push = |id, value, detail| feats.push((id, value, detail));

    macro_rules! bits {
        ($reg:expr, $leaf:literal, $name:literal, $( $id:literal => $bit:literal ),+ $(,)?) => {
            $(push($id, bit($reg, $bit), concat!($leaf, ":", $name, "[", stringify!($bit), "]"));)+
        };
    }

    bits!(l1d, "CPUID.01H", "EDX", "sse"=>25, "sse2"=>26, "htt"=>28);
    bits!(l1c, "CPUID.01H", "ECX", "sse3"=>0, "pclmulqdq"=>1, "ssse3"=>9,
        "fma"=>12, "cmpxchg16b"=>13, "sse4_1"=>19, "sse4_2"=>20,
        "x2apic"=>21, "popcnt"=>23, "aes"=>25, "xsave"=>26, "avx"=>28,
        "f16c"=>29, "rdrand"=>30, "hypervisor"=>31);

    let (_, l7b, l7c, l7d) = if max_basic >= 7 {
        cpuid(7, 0)
    } else {
        (0, 0, 0, 0)
    };
    bits!(l7b, "CPUID.07H.0", "EBX", "fsgsbase"=>0, "bmi1"=>3, "avx2"=>5,
        "smep"=>7, "bmi2"=>8, "avx512f"=>16, "avx512dq"=>17, "rdseed"=>18,
        "adx"=>19, "smap"=>20, "avx512ifma"=>21, "clflushopt"=>23, "clwb"=>24,
        "avx512cd"=>28, "sha"=>29, "avx512bw"=>30, "avx512vl"=>31);
    bits!(l7c, "CPUID.07H.0", "ECX", "avx512vbmi"=>1, "umip"=>2, "pku"=>3,
        "ospke"=>4, "avx512vbmi2"=>6, "gfni"=>8, "vaes"=>9, "vpclmulqdq"=>10,
        "avx512vnni"=>11, "avx512bitalg"=>12, "avx512vpopcntdq"=>14,
        "rdpid"=>22, "movdiri"=>27, "movdir64b"=>28);
    bits!(l7d, "CPUID.07H.0", "EDX", "serialize"=>14, "avx512fp16"=>23);
    let (l71a, _, _, _) = if max_basic >= 7 && cpuid(7, 0).0 >= 1 {
        cpuid(7, 1)
    } else {
        (0, 0, 0, 0)
    };
    bits!(l71a, "CPUID.07H.1", "EAX", "avx_vnni"=>4, "avx512bf16"=>5);

    let (_, _, e1c, e1d) = if max_ext >= 0x8000_0001 {
        cpuid(0x8000_0001, 0)
    } else {
        (0, 0, 0, 0)
    };
    bits!(e1c, "CPUID.80000001H", "ECX", "svm"=>2, "abm"=>5, "sse4a"=>6,
        "ibs"=>10, "xop"=>11, "fma4"=>16, "tbm"=>21, "topoext"=>22,
        "perfctr_core"=>23, "perfctr_nb"=>24, "mwaitx"=>29);
    bits!(e1d, "CPUID.80000001H", "EDX", "nx"=>20, "rdtscp"=>27);

    let (_, _, _, e7d) = if max_ext >= 0x8000_0007 {
        cpuid(0x8000_0007, 0)
    } else {
        (0, 0, 0, 0)
    };
    bits!(e7d, "CPUID.80000007H", "EDX", "invariant_tsc"=>8, "cpb"=>9);

    let (_, e8b, _, _) = if max_ext >= 0x8000_0008 {
        cpuid(0x8000_0008, 0)
    } else {
        (0, 0, 0, 0)
    };
    bits!(e8b, "CPUID.80000008H", "EBX", "clzero"=>0, "rdpru"=>4, "wbnoinvd"=>9,
        "ibpb"=>12, "ibrs"=>14, "stibp"=>15, "ssbd"=>24, "virt_ssbd"=>25,
        "ssb_no"=>26, "cppc"=>27, "psfd"=>28, "btc_no"=>29);

    let (_, _, _, ead) = if max_ext >= 0x8000_000a {
        cpuid(0x8000_000a, 0)
    } else {
        (0, 0, 0, 0)
    };
    bits!(ead, "CPUID.8000000AH", "EDX", "npt"=>0, "lbrv"=>1, "svm_lock"=>2,
        "nrip_save"=>3, "tsc_scale"=>4, "vmcb_clean"=>5, "flushbyasid"=>6,
        "decodeassists"=>7, "pausefilter"=>10, "avic"=>13, "v_vmsave_vmload"=>15, "vgif"=>16);

    let (e1fa, _, _, _) = if max_ext >= 0x8000_001f {
        cpuid(0x8000_001f, 0)
    } else {
        (0, 0, 0, 0)
    };
    bits!(e1fa, "CPUID.8000001FH", "EAX", "sme"=>0, "sev"=>1, "sev_es"=>3,
        "sev_snp"=>4, "vmpl"=>5, "vte"=>16);
    let (e22a, _, _, _) = if max_ext >= 0x8000_0022 {
        cpuid(0x8000_0022, 0)
    } else {
        (0, 0, 0, 0)
    };
    push("perfmon_v2", bit(e22a, 0), "CPUID.80000022H:EAX[0]");
    push(
        "arch_perfmon",
        max_basic >= 0xA && (cpuid(0xA, 0).0 & 0xff) != 0,
        "CPUID.0AH:EAX[7:0]",
    );

    let (d1a, _, _, _) = if max_basic >= 0xD {
        cpuid(0xD, 1)
    } else {
        (0, 0, 0, 0)
    };
    bits!(d1a, "CPUID.0DH.1", "EAX", "xsaveopt"=>0, "xsavec"=>1, "xsaves"=>3);

    let (eax1, _, _, _) = cpuid(1, 0);
    let base_family = (eax1 >> 8) & 0xf;
    let base_model = (eax1 >> 4) & 0xf;
    let family = if base_family == 0xf {
        base_family + ((eax1 >> 20) & 0xff)
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        base_model | (((eax1 >> 16) & 0xf) << 4)
    } else {
        base_model
    };
    let brand = brand_string(max_ext);
    CoreScan {
        logical_cpu,
        physical_key: physical_core_key(logical_cpu, max_basic, ctx),
        feats,
        ident: CoreIdent {
            vendor,
            brand,
            family,
            model,
            stepping: eax1 & 0xf,
        },
    }
}

#[cfg(target_arch = "x86_64")]
fn brand_string(max_ext: u32) -> String {
    if max_ext < 0x8000_0004 {
        return String::new();
    }
    let mut bytes = Vec::with_capacity(48);
    for leaf in 0x8000_0002..=0x8000_0004 {
        let (a, b, c, d) = raw::cpuid(leaf, 0);
        for word in [a, b, c, d] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    String::from_utf8_lossy(&bytes)
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

#[cfg(target_arch = "x86_64")]
fn aggregate(cores: &[CoreScan]) -> Vec<(&'static str, Detection)> {
    let total = cores.len();
    cores[0]
        .feats
        .iter()
        .enumerate()
        .map(|(index, &(id, _, detail))| {
            let count = cores
                .iter()
                .filter(|core| core.feats.get(index).is_some_and(|f| f.1))
                .count();
            let detection = match count {
                0 => Detection::with_detail(Status::Absent, "cpuid", detail),
                n if n == total => Detection::with_detail(Status::Present, "cpuid", detail),
                n => Detection::with_detail(
                    Status::Present,
                    "cpuid",
                    format!("{detail}; asymmetric: {n}/{total} logical CPUs"),
                ),
            };
            (id, detection)
        })
        .collect()
}

#[cfg(target_arch = "x86_64")]
fn build_identity(cores: &[CoreScan], ctx: &Context) -> Identity {
    let first = &cores[0].ident;
    Identity {
        vendor: first.vendor.clone(),
        brand: first.brand.clone(),
        family: first.family,
        model: first.model,
        stepping: first.stepping,
        model_info: cpu_db::lookup_with_brand(
            &first.vendor,
            first.family,
            first.model,
            &first.brand,
        ),
        logical_cpus: cores.len(),
        hybrid: false,
        p_cores: physical_core_count(cores),
        e_cores: 0,
        microcode: read_microcode(ctx),
    }
}

#[cfg(target_arch = "x86_64")]
fn physical_core_count(cores: &[CoreScan]) -> usize {
    cores
        .iter()
        .map(|core| {
            core.physical_key
                .unwrap_or(u64::from(core.logical_cpu) | (1 << 63))
        })
        .collect::<HashSet<_>>()
        .len()
}

#[cfg(target_arch = "x86_64")]
fn read_microcode(ctx: &Context) -> Option<String> {
    ctx.reader
        .read_to_string(Path::new("/sys/devices/system/cpu/cpu0/microcode/version"))
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| {
            let info = ctx.reader.read_to_string(Path::new("/proc/cpuinfo")).ok()?;
            info.lines().find_map(|line| {
                line.strip_prefix("microcode")?
                    .split_once(':')
                    .map(|(_, v)| v.trim().to_string())
            })
        })
}

#[cfg(target_arch = "x86_64")]
fn physical_core_key(cpu: u32, max_basic: u32, ctx: &Context) -> Option<u64> {
    // Linux topology is preferred: AMD's pre-Zen and multi-die topology encodings vary.
    let base = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
    let package = ctx
        .reader
        .read_to_string(Path::new(&format!("{base}/physical_package_id")))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    let core = ctx
        .reader
        .read_to_string(Path::new(&format!("{base}/core_id")))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    let _ = max_basic;
    Some((u64::from(package) << 32) | u64::from(core))
}

#[cfg(target_arch = "x86_64")]
fn parse_cpu_list(text: &str) -> Option<Vec<u32>> {
    let mut cpus = Vec::new();
    for part in text.trim().split(',').filter(|part| !part.is_empty()) {
        if let Some((first, last)) = part.split_once('-') {
            let first = first.parse::<u32>().ok()?;
            let last = last.parse::<u32>().ok()?;
            if first > last {
                return None;
            }
            cpus.extend(first..=last);
        } else {
            cpus.push(part.parse().ok()?);
        }
    }
    (!cpus.is_empty()).then_some(cpus)
}

#[cfg(target_arch = "x86_64")]
fn eligible_cpus(ctx: &Context) -> Vec<u32> {
    let allowed = ctx
        .reader
        .read_to_string(Path::new("/proc/self/status"))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("Cpus_allowed_list:")
                    .map(str::trim)
                    .and_then(parse_cpu_list)
            })
        });
    let online = ctx
        .reader
        .read_to_string(Path::new("/sys/devices/system/cpu/online"))
        .ok()
        .and_then(|text| parse_cpu_list(&text));
    let (Some(allowed), Some(online)) = (allowed, online) else {
        return Vec::new();
    };
    let online: HashSet<_> = online.into_iter().collect();
    allowed
        .into_iter()
        .filter(|cpu| online.contains(cpu))
        .collect()
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    #[test]
    fn cpu_list_supports_sparse_and_high_ids() {
        assert_eq!(
            parse_cpu_list("2-3,1024,4096"),
            Some(vec![2, 3, 1024, 4096])
        );
        assert_eq!(parse_cpu_list("4-2"), None);
        assert_eq!(parse_cpu_list("garbage"), None);
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn run_scan(_ctx: &Context) -> Scan {
    Scan {
        identity: None,
        detections: Vec::new(),
    }
}
