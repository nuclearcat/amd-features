//! Conservative expectations for recognized AMD hardware classes.
//!
//! Detection answers what this machine exposes. Expectations answer a different
//! question: what should, or could, a processor in the same architectural class
//! expose? Keeping the two separate prevents an expectation from becoming a false
//! hardware detection.

use serde::Serialize;

use crate::model::Status;
use crate::probes::cpuid::Identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectationLevel {
    /// Architectural baseline for the recognized generation/class.
    Expected,
    /// Available on some products or dependent on firmware/OS integration.
    Available,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attention {
    Warning,
    Critical,
}

impl Attention {
    pub fn color(self) -> &'static str {
        match self {
            Self::Warning => "33",
            Self::Critical => "31",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Expectation {
    pub level: ExpectationLevel,
    pub profile: &'static str,
    pub rationale: &'static str,
}

impl Expectation {
    pub fn attention(self, status: Status) -> Option<Attention> {
        if !matches!(status, Status::Absent | Status::Disabled) {
            return None;
        }
        Some(match self.level {
            ExpectationLevel::Expected => Attention::Critical,
            ExpectationLevel::Available => Attention::Warning,
        })
    }
}

const ZEN_BASELINE: &[&str] = &[
    "avx",
    "avx2",
    "fma",
    "bmi1",
    "bmi2",
    "aes",
    "sha",
    "nx",
    "smep",
    "smap",
    "svm",
    "npt",
    "ibs",
    "invariant_tsc",
    "topoext",
    "cpb",
];

const AVX512_BASELINE: &[&str] = &["avx512f", "avx512dq", "avx512cd", "avx512bw", "avx512vl"];

const AVX512_OPTIONAL_SUBSETS: &[&str] = &[
    "avx512ifma",
    "avx512vbmi",
    "avx512vbmi2",
    "avx512vnni",
    "avx512bitalg",
    "avx512vpopcntdq",
    "avx512bf16",
];

const ZEN_PLATFORM_OPTIONS: &[&str] = &["sme", "amd_vi", "hwmon"];

const MODERN_PLATFORM_OPTIONS: &[&str] = &[
    "amd_pstate",
    "energy",
    "l3_cat",
    "l3_monitoring",
    "mba",
    "resctrl",
];

/// Return the expectation attached to `feature_id` for this processor class.
/// Unknown families and non-AMD vendors deliberately produce no expectations.
pub fn for_feature(identity: Option<&Identity>, feature_id: &str) -> Option<Expectation> {
    let identity = identity?;
    if !matches!(identity.vendor.as_str(), "AuthenticAMD" | "HygonGenuine") {
        return None;
    }

    let profile = profile(identity.family, identity.model)?;
    if ZEN_BASELINE.contains(&feature_id) {
        return Some(expected(
            profile.name,
            "architectural baseline for this AMD Zen class",
        ));
    }

    if profile.avx512 && AVX512_BASELINE.contains(&feature_id) {
        return Some(expected(
            profile.name,
            "AVX-512 baseline for Zen 4 and later; firmware may disable AVX-512",
        ));
    }
    if profile.avx512 && AVX512_OPTIONAL_SUBSETS.contains(&feature_id) {
        return Some(available(
            profile.name,
            "AVX-512 subset available on processors in this generation",
        ));
    }
    if profile.zen5 && feature_id == "avx512fp16" {
        return Some(available(
            profile.name,
            "AVX-512 FP16 is available on some Zen 5 products",
        ));
    }
    if profile.modern && feature_id == "cppc" {
        return Some(expected(
            profile.name,
            "CPPC capability expected on this modern Zen class",
        ));
    }
    if ZEN_PLATFORM_OPTIONS.contains(&feature_id) {
        return Some(available(
            profile.name,
            "platform, firmware, or product configuration dependent",
        ));
    }
    if profile.modern && MODERN_PLATFORM_OPTIONS.contains(&feature_id) {
        return Some(available(
            profile.name,
            "supported on some systems; requires firmware and/or OS integration",
        ));
    }

    let brand = identity.brand.to_ascii_lowercase();
    if brand.contains("epyc") {
        if feature_id == "memory_ecc" {
            return Some(expected(
                "AMD EPYC",
                "ECC memory support is part of the server class",
            ));
        }
        if matches!(feature_id, "sev" | "sev_es" | "sev_snp") {
            return Some(available(
                "AMD EPYC",
                "secure-virtualization capability varies by generation and firmware",
            ));
        }
    }
    if brand.contains("ryzen ai") && feature_id == "npu" {
        return Some(expected(
            "AMD Ryzen AI",
            "Ryzen AI product-class accelerator",
        ));
    }
    None
}

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    avx512: bool,
    zen5: bool,
    modern: bool,
}

fn profile(family: u32, model: u32) -> Option<Profile> {
    use crate::cpu_db::{zen_generation, ZenGeneration};
    let profile = match zen_generation(family, model)? {
        ZenGeneration::Zen | ZenGeneration::Zen2 => Profile {
            name: "AMD Zen / Zen 2",
            avx512: false,
            zen5: false,
            modern: false,
        },
        ZenGeneration::Zen3 => Profile {
            name: "AMD Zen 3",
            avx512: false,
            zen5: false,
            modern: true,
        },
        ZenGeneration::Zen4 => Profile {
            name: "AMD Zen 4",
            avx512: true,
            zen5: false,
            modern: true,
        },
        ZenGeneration::Zen5 => Profile {
            name: "AMD Zen 5",
            avx512: true,
            zen5: true,
            modern: true,
        },
        ZenGeneration::Zen6 => Profile {
            name: "AMD Zen 6",
            avx512: true,
            zen5: false,
            modern: true,
        },
    };
    Some(profile)
}

fn expected(profile: &'static str, rationale: &'static str) -> Expectation {
    Expectation {
        level: ExpectationLevel::Expected,
        profile,
        rationale,
    }
}

fn available(profile: &'static str, rationale: &'static str) -> Expectation {
    Expectation {
        level: ExpectationLevel::Available,
        profile,
        rationale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::cpuid::Identity;

    fn zen5(brand: &str) -> Identity {
        Identity {
            vendor: "AuthenticAMD".into(),
            brand: brand.into(),
            family: 0x1a,
            model: 0x44,
            stepping: 0,
            model_info: None,
            logical_cpus: 16,
            hybrid: false,
            p_cores: 8,
            e_cores: 0,
            microcode: None,
        }
    }

    #[test]
    fn zen5_avx512_foundation_is_expected() {
        let expectation = for_feature(Some(&zen5("AMD Ryzen")), "avx512f").unwrap();
        assert_eq!(expectation.level, ExpectationLevel::Expected);
        assert_eq!(
            expectation.attention(Status::Absent),
            Some(Attention::Critical)
        );
    }

    #[test]
    fn zen5_fp16_is_possible_not_mandatory() {
        let expectation = for_feature(Some(&zen5("AMD Ryzen")), "avx512fp16").unwrap();
        assert_eq!(expectation.level, ExpectationLevel::Available);
        assert_eq!(
            expectation.attention(Status::Absent),
            Some(Attention::Warning)
        );
    }

    #[test]
    fn present_features_never_raise_attention() {
        let expectation = for_feature(Some(&zen5("AMD Ryzen")), "avx512f").unwrap();
        assert_eq!(expectation.attention(Status::Present), None);
    }

    #[test]
    fn genoa_avx512_foundation_is_expected() {
        let genoa = Identity {
            vendor: "AuthenticAMD".into(),
            brand: "AMD EPYC 9654 96-Core Processor".into(),
            family: 0x19,
            model: 0x11,
            stepping: 1,
            model_info: None,
            logical_cpus: 192,
            hybrid: false,
            p_cores: 96,
            e_cores: 0,
            microcode: None,
        };
        let expectation = for_feature(Some(&genoa), "avx512f").unwrap();
        assert_eq!(expectation.level, ExpectationLevel::Expected);
        assert_eq!(expectation.profile, "AMD Zen 4");
    }
}
