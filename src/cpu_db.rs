//! AMD CPUID display-family/model identification.
//!
//! Model ranges are taken from public CPUID decode tables (LLVM `Host.cpp`, InstLatX64
//! dumps, and AMD revision guides). When one model range is shared by more than one
//! product segment, the processor brand string is used only to choose among those
//! known aliases. Unrecognized brands keep a slash-separated name rather than guessing.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CpuModelInfo {
    pub codename: &'static str,
    pub generation: &'static str,
    pub segment: &'static str,
}

/// Architectural generation used by class-aware expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZenGeneration {
    Zen,
    Zen2,
    Zen3,
    Zen4,
    Zen5,
    Zen6,
}

const fn info(
    codename: &'static str,
    generation: &'static str,
    segment: &'static str,
) -> CpuModelInfo {
    CpuModelInfo {
        codename,
        generation,
        segment,
    }
}

pub fn lookup(vendor: &str, family: u32, model: u32) -> Option<CpuModelInfo> {
    lookup_with_brand(vendor, family, model, "")
}

pub fn lookup_with_brand(
    vendor: &str,
    family: u32,
    model: u32,
    brand: &str,
) -> Option<CpuModelInfo> {
    if !matches!(vendor, "AuthenticAMD" | "HygonGenuine") {
        return None;
    }
    match (family, model) {
        (0x10, _) => Some(info("K10", "Family 10h", "client/server")),
        (0x12, _) => Some(info("Llano", "Family 12h", "mobile/desktop APU")),
        (0x14, _) => Some(info("Bobcat", "Family 14h", "low-power client")),
        (0x15, 0x02 | 0x10..=0x2f) => Some(info("Piledriver", "Family 15h", "client/server/APU")),
        (0x15, 0x00..=0x0f) => Some(info("Bulldozer", "Family 15h", "client/server")),
        (0x15, 0x30..=0x3f) => Some(info("Steamroller", "Family 15h", "client/APU")),
        (0x15, 0x60..=0x7f) => Some(info("Excavator", "Family 15h", "client/APU")),
        (0x15, _) => Some(info("Family 15h processor", "Family 15h", "client/server")),
        (0x16, 0x00..=0x0f) => Some(info("Jaguar", "Family 16h", "low-power client/embedded")),
        (0x16, 0x30..=0x3f) => Some(info("Puma", "Family 16h", "low-power client/embedded")),
        (0x16, _) => Some(info(
            "Jaguar/Puma",
            "Family 16h",
            "low-power client/embedded",
        )),

        (0x17, 0x00..=0x07) => Some(pick(
            brand,
            info("Naples", "Zen", "server"),
            info("Whitehaven", "Zen", "HEDT"),
            info("Summit Ridge", "Zen", "desktop"),
            info("Summit Ridge/Naples", "Zen", "client/server"),
        )),
        (0x17, 0x08..=0x0f) => Some(pick(
            brand,
            info("Pinnacle Ridge/Colfax", "Zen+", "client/HEDT"),
            info("Colfax", "Zen+", "HEDT"),
            info("Pinnacle Ridge", "Zen+", "desktop"),
            info("Pinnacle Ridge/Colfax", "Zen+", "client/HEDT"),
        )),
        (0x17, 0x10..=0x17) => Some(info("Raven Ridge", "Zen", "client APU")),
        (0x17, 0x18..=0x1f) => Some(info("Picasso", "Zen+", "client APU")),
        (0x17, 0x20..=0x2f) => Some(info("Dali", "Zen/Zen+", "low-power APU")),
        (0x17, 0x30..=0x3f) => Some(pick(
            brand,
            info("Rome", "Zen 2", "server"),
            info("Castle Peak", "Zen 2", "HEDT"),
            info("Rome/Castle Peak", "Zen 2", "server/HEDT"),
            info("Rome/Castle Peak", "Zen 2", "server/HEDT"),
        )),
        (0x17, 0x47) => Some(info("Cardinal", "Zen 2", "custom/embedded")),
        (0x17, 0x60..=0x67) => Some(info("Renoir", "Zen 2", "mobile/desktop APU")),
        (0x17, 0x68..=0x6f) => Some(info("Lucienne", "Zen 2", "mobile/desktop APU")),
        (0x17, 0x70..=0x7f) => Some(info("Matisse", "Zen 2", "desktop")),
        (0x17, 0x90..=0x97) => Some(info("Van Gogh", "Zen 2", "low-power APU")),
        (0x17, 0x98..=0x9f) => Some(info("Mero", "Zen 2", "low-power APU")),
        (0x17, 0xa0..=0xaf) => Some(info("Mendocino", "Zen 2", "low-power APU")),
        (0x17, _) => Some(info("Zen-family processor", "Family 17h", "client/server")),

        (0x18, _) => Some(info("Dhyana", "Hygon Family 18h", "server")),

        (0x19, 0x00..=0x0f) => Some(pick(
            brand,
            info("Milan", "Zen 3", "server"),
            info("Chagall", "Zen 3", "HEDT"),
            info("Milan/Chagall", "Zen 3", "server/HEDT"),
            info("Milan/Chagall", "Zen 3", "server/HEDT"),
        )),
        (0x19, 0x10..=0x1f) => Some(pick(
            brand,
            info("Genoa", "Zen 4", "server"),
            info("Storm Peak", "Zen 4", "HEDT"),
            info("Genoa/Storm Peak", "Zen 4", "server/HEDT"),
            info("Genoa/Storm Peak", "Zen 4", "server/HEDT"),
        )),
        (0x19, 0x20..=0x2f) => Some(info("Vermeer", "Zen 3", "desktop")),
        (0x19, 0x30..=0x3f) => Some(info("Badami", "Zen 3", "server")),
        (0x19, 0x40..=0x4f) => Some(info("Rembrandt", "Zen 3+", "client APU")),
        (0x19, 0x50..=0x5f) => Some(info("Cezanne/Barcelo", "Zen 3", "client APU")),
        (0x19, 0x60..=0x6f) => Some(info("Raphael", "Zen 4", "desktop/mobile")),
        (0x19, 0x70..=0x77) => Some(info("Phoenix/Hawk Point", "Zen 4", "client APU")),
        (0x19, 0x78..=0x7f) => Some(info("Phoenix 2/Hawk Point 2", "Zen 4/Zen 4c", "client APU")),
        (0x19, 0xa0..=0xaf) => Some(info("Bergamo/Siena", "Zen 4c", "server")),
        (0x19, _) => Some(info("Zen-family processor", "Family 19h", "client/server")),

        (0x1a, 0x00..=0x0f) => Some(info("Turin", "Zen 5", "server")),
        (0x1a, 0x10..=0x1f) => Some(info("Turin Dense", "Zen 5c", "server")),
        (0x1a, 0x20..=0x3f) => Some(info("Strix Point", "Zen 5/Zen 5c", "client APU")),
        (0x1a, 0x40..=0x4f) => Some(info("Granite Ridge/Fire Range", "Zen 5", "desktop/mobile")),
        (0x1a, 0x60..=0x6f) => Some(info("Krackan Point", "Zen 5/Zen 5c", "client APU")),
        (0x1a, 0x70..=0x77) => Some(info("Strix Halo", "Zen 5", "client APU")),
        (0x1a, 0xd0..=0xd7) => Some(info("Annapurna", "Zen 5", "server")),
        (0x1a, model) if is_znver6(model) => {
            Some(info("Zen 6-family processor", "Zen 6", "client/server"))
        }
        (0x1a, _) => Some(info("Zen-family processor", "Family 1Ah", "client/server")),
        _ => None,
    }
}

/// Map a recognized AMD family/model onto the Zen generation used for expectations.
/// Unknown families and unmapped Family 1Ah models return `None`.
pub fn zen_generation(family: u32, model: u32) -> Option<ZenGeneration> {
    match (family, model) {
        (0x17, 0x30..=0x3f | 0x47 | 0x60..=0x7f | 0x84..=0x87 | 0x90..=0x9f | 0xa0..=0xaf) => {
            Some(ZenGeneration::Zen2)
        }
        (0x17, _) => Some(ZenGeneration::Zen),
        (0x19, 0x10..=0x1f | 0x60..=0x7f | 0xa0..=0xaf) => Some(ZenGeneration::Zen4),
        (0x19, _) => Some(ZenGeneration::Zen3),
        (0x1a, model) if is_znver6(model) => Some(ZenGeneration::Zen6),
        (0x1a, 0x00..=0x4f | 0x60..=0x77 | 0xd0..=0xd7) => Some(ZenGeneration::Zen5),
        _ => None,
    }
}

fn is_znver6(model: u32) -> bool {
    matches!(model, 0x50..=0x5f | 0x80..=0xcf | 0xd8..=0xe7)
}

fn pick(
    brand: &str,
    epyc: CpuModelInfo,
    threadripper: CpuModelInfo,
    ryzen: CpuModelInfo,
    other: CpuModelInfo,
) -> CpuModelInfo {
    let brand = brand.to_ascii_uppercase();
    if brand.contains("EPYC") {
        epyc
    } else if brand.contains("THREADRIPPER") {
        threadripper
    } else if brand.contains("RYZEN") || brand.contains("ATHLON") {
        ryzen
    } else {
        other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amd(family: u32, model: u32) -> CpuModelInfo {
        lookup("AuthenticAMD", family, model).unwrap()
    }

    fn branded(family: u32, model: u32, brand: &str) -> CpuModelInfo {
        lookup_with_brand("AuthenticAMD", family, model, brand).unwrap()
    }

    #[test]
    fn identifies_zen4_raphael() {
        let processor = amd(0x19, 0x61);
        assert_eq!(processor.codename, "Raphael");
        assert_eq!(processor.generation, "Zen 4");
        assert_ne!(processor.codename, "Raphael/Genoa");
    }

    #[test]
    fn genoa_is_zen4_not_milan() {
        let processor = branded(0x19, 0x11, "AMD EPYC 9654 96-Core Processor");
        assert_eq!(processor.codename, "Genoa");
        assert_eq!(processor.generation, "Zen 4");
        assert_eq!(zen_generation(0x19, 0x11), Some(ZenGeneration::Zen4));
    }

    #[test]
    fn matisse_is_not_renoir() {
        let processor = amd(0x17, 0x71);
        assert_eq!(processor.codename, "Matisse");
        assert_eq!(processor.generation, "Zen 2");
        assert_eq!(processor.segment, "desktop");
    }

    #[test]
    fn renoir_stays_an_apu_range() {
        let processor = amd(0x17, 0x60);
        assert_eq!(processor.codename, "Renoir");
        assert_eq!(processor.segment, "mobile/desktop APU");
    }

    #[test]
    fn family_1a_model_44_is_desktop_not_an_apu() {
        let processor = amd(0x1a, 0x44);
        assert_eq!(processor.codename, "Granite Ridge/Fire Range");
        assert_eq!(processor.generation, "Zen 5");
        assert_eq!(processor.segment, "desktop/mobile");
        assert!(!processor.segment.to_ascii_lowercase().contains("apu"));
    }

    #[test]
    fn strix_point_is_client_apu() {
        let processor = amd(0x1a, 0x24);
        assert_eq!(processor.codename, "Strix Point");
        assert_eq!(processor.segment, "client APU");
    }

    #[test]
    fn ryzen_brand_picks_client_name_in_shared_zen1_range() {
        assert_eq!(
            branded(0x17, 0x01, "AMD Ryzen 7 1800X Eight-Core Processor").codename,
            "Summit Ridge"
        );
        assert_eq!(
            branded(0x17, 0x08, "AMD Ryzen 7 2700X Eight-Core Processor").codename,
            "Pinnacle Ridge"
        );
    }

    #[test]
    fn brand_disambiguates_shared_server_hedt_ranges() {
        assert_eq!(
            branded(0x19, 0x01, "AMD EPYC 7763 64-Core Processor").codename,
            "Milan"
        );
        assert_eq!(
            branded(0x19, 0x08, "AMD Ryzen Threadripper PRO 5995WX 64-Cores").codename,
            "Chagall"
        );
        assert_eq!(
            branded(0x17, 0x31, "AMD EPYC 7742 64-Core Processor").codename,
            "Rome"
        );
        assert_eq!(
            branded(0x17, 0x31, "AMD Ryzen Threadripper 3990X 64-Core Processor").codename,
            "Castle Peak"
        );
    }

    #[test]
    fn excavator_is_identified() {
        assert_eq!(amd(0x15, 0x65).codename, "Excavator");
    }

    #[test]
    fn zen6_family_1ah_is_not_labeled_zen5() {
        let processor = amd(0x1a, 0x50);
        assert_eq!(processor.generation, "Zen 6");
        assert_eq!(zen_generation(0x1a, 0x50), Some(ZenGeneration::Zen6));
        assert_eq!(zen_generation(0x1a, 0x44), Some(ZenGeneration::Zen5));
    }

    #[test]
    fn rejects_non_amd() {
        assert_eq!(lookup("GenuineIntel", 0x19, 0x61), None);
    }
}
