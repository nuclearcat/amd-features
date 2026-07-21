//! Conservative AMD CPUID display-family/model identification.
//!
//! AMD model ranges often span client and server products or later refreshes. Entries
//! intentionally use family-level names where a model alone is not unambiguous.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CpuModelInfo {
    pub codename: &'static str,
    pub generation: &'static str,
    pub segment: &'static str,
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
    if !matches!(vendor, "AuthenticAMD" | "HygonGenuine") {
        return None;
    }
    match (family, model) {
        (0x10, _) => Some(info("K10", "Family 10h", "client/server")),
        (0x12, _) => Some(info("Llano", "Family 12h", "mobile/desktop APU")),
        (0x14, _) => Some(info("Bobcat", "Family 14h", "low-power client")),
        (0x15, 0x00..=0x0f) => Some(info("Bulldozer", "Family 15h", "client/server")),
        (0x15, 0x10..=0x2f) => Some(info("Piledriver", "Family 15h", "client/server/APU")),
        (0x15, 0x30..=0x5f) => Some(info("Steamroller/Excavator", "Family 15h", "client/APU")),
        (0x16, _) => Some(info(
            "Jaguar/Puma",
            "Family 16h",
            "low-power client/embedded",
        )),
        (0x17, 0x00..=0x0f) => Some(info("Summit Ridge/Naples", "Zen", "client/server")),
        (0x17, 0x10..=0x2f) => Some(info("Raven Ridge/Picasso", "Zen/Zen+", "client APU")),
        (0x17, 0x30..=0x3f) => Some(info("Rome", "Zen 2", "server")),
        (0x17, 0x60..=0x7f) => Some(info("Renoir/Lucienne", "Zen 2", "mobile/desktop APU")),
        (0x17, 0x90..=0xaf) => Some(info("Van Gogh/Mendocino", "Zen 2", "low-power APU")),
        (0x17, _) => Some(info("Zen-family processor", "Family 17h", "client/server")),
        (0x18, _) => Some(info("Dhyana", "Hygon Family 18h", "server")),
        (0x19, 0x00..=0x0f) => Some(info("Milan", "Zen 3", "server")),
        (0x19, 0x20..=0x2f) => Some(info("Vermeer", "Zen 3", "desktop")),
        (0x19, 0x40..=0x5f) => Some(info(
            "Rembrandt/Cezanne/Barcelo",
            "Zen 3/Zen 3+",
            "client APU",
        )),
        (0x19, 0x60..=0x6f) => Some(info("Raphael/Genoa", "Zen 4", "desktop/server")),
        (0x19, 0x70..=0x7f) => Some(info("Phoenix/Hawk Point", "Zen 4", "client APU")),
        (0x19, 0xa0..=0xaf) => Some(info("Bergamo/Siena", "Zen 4c", "server")),
        (0x19, _) => Some(info("Zen-family processor", "Family 19h", "client/server")),
        (0x1a, 0x00..=0x0f) => Some(info("Turin", "Zen 5", "server")),
        // Public family/model documentation does not uniquely identify every client
        // product codename. Keep these labels deliberately conservative: model 44h,
        // for example, is used by desktop Ryzen 9000 processors.
        (0x1a, 0x20..=0x2f) => Some(info("Zen 5 client processor", "Zen 5/Zen 5c", "client")),
        (0x1a, 0x40..=0x4f) => Some(info("Zen 5 client processor", "Zen 5", "desktop/client")),
        (0x1a, 0x70..=0x7f) => Some(info("Zen 5-family processor", "Zen 5", "client/server")),
        (0x1a, _) => Some(info(
            "Zen 5-family processor",
            "Family 1Ah",
            "client/server",
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifies_zen4() {
        assert_eq!(
            lookup("AuthenticAMD", 0x19, 0x61).unwrap().generation,
            "Zen 4"
        );
    }
    #[test]
    fn family_1a_model_44_is_not_mislabeled_as_an_apu() {
        let processor = lookup("AuthenticAMD", 0x1a, 0x44).unwrap();
        assert_eq!(processor.generation, "Zen 5");
        assert_eq!(processor.segment, "desktop/client");
    }
    #[test]
    fn rejects_non_amd() {
        assert_eq!(lookup("GenuineIntel", 0x19, 0x61), None);
    }
}
