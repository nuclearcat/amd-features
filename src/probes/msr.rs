//! Read-only AMD model-specific-register probe.
//!
//! Only AMD-documented architectural MSRs are queried. Module loading remains an
//! explicit root-only opt-in and no register is ever written.

use std::io;
use std::path::Path;

use crate::model::{Detection, Status};
use crate::probes::{
    finding_detail, unavailable, Context, Findings, MsrAccess, Probe, ProbeResult,
};

pub struct MsrProbe;
const SRC: &str = "msr";
const FEATURES: &[&str] = &[
    "msr",
    "svm",
    "svm_runtime",
    "hwcr",
    "sme_active",
    "sev",
    "sev_es",
    "sev_snp",
    "pstate_status",
];

const MSR_AMD64_SYSCFG: u32 = 0xc001_0010;
const MSR_K7_HWCR: u32 = 0xc001_0015;
const MSR_AMD_PSTATE_STATUS: u32 = 0xc001_0063;
const MSR_VM_CR: u32 = 0xc001_0114;
const MSR_AMD64_SEV: u32 = 0xc001_0131;

impl Probe for MsrProbe {
    fn name(&self) -> &'static str {
        SRC
    }
    fn feature_ids(&self) -> Vec<&'static str> {
        FEATURES.to_vec()
    }
    fn detect(&self, ctx: &Context) -> ProbeResult {
        let mut out = Vec::new();
        match acquire(ctx) {
            Ok(detail) => out.push(("msr", Detection::with_detail(Status::Enabled, SRC, detail))),
            Err(reason) => return Ok(unavailable(SRC, FEATURES, reason)),
        }
        if !is_amd_cpu() {
            return Ok(unavailable(
                SRC,
                FEATURES,
                "MSR decode is only valid on AMD/Hygon CPUs",
            ));
        }
        svm_state(ctx.msr.as_ref(), &mut out);
        memory_encryption(ctx.msr.as_ref(), &mut out);
        values(ctx.msr.as_ref(), &mut out);
        for &id in FEATURES {
            if !out.iter().any(|(found, _)| *found == id) {
                out.push(finding_detail(
                    SRC,
                    id,
                    Status::Unknown,
                    "required AMD MSR unavailable on this processor",
                ));
            }
        }
        Ok(out)
    }
}

fn acquire(ctx: &Context) -> Result<String, String> {
    let path = Path::new("/dev/cpu/0/msr");
    match ctx.reader.open_device(path, false) {
        Ok(()) => return Ok("/dev/cpu/0/msr readable".into()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return Err("requires permission to read /dev/cpu/0/msr".into())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if !ctx.options.load_msr_module {
                return Err(
                    "no /dev/cpu/0/msr (use --load-msr-module to opt in to modprobe)".into(),
                );
            }
            if !ctx.is_root() {
                return Err("--load-msr-module requires root".into());
            }
        }
        Err(error) => return Err(format!("open failed: {:?}", error.kind())),
    }
    if !ctx.try_mark_module_load() {
        return Err("msr module load was already attempted".into());
    }
    ctx.msr
        .load_module()
        .map_err(|reason| format!("modprobe msr failed: {reason}"))?;
    ctx.reader
        .open_device(path, false)
        .map(|_| "readable (loaded msr module by explicit request)".into())
        .map_err(|error| format!("msr module loaded but open failed: {:?}", error.kind()))
}

fn read(msr: &dyn MsrAccess, register: u32) -> io::Result<u64> {
    msr.read(0, register)
}
fn bit(value: u64, bit: u32) -> bool {
    ((value >> bit) & 1) != 0
}

fn svm_state(msr: &dyn MsrAccess, out: &mut Findings) {
    let Ok(value) = read(msr, MSR_VM_CR) else {
        return;
    };
    let locked = bit(value, 3);
    let disabled = bit(value, 4);
    let status = if disabled {
        Status::Disabled
    } else {
        Status::Enabled
    };
    let detail = format!(
        "VM_CR={value:#x}; SVM {}; firmware lock {}",
        if disabled { "disabled" } else { "enabled" },
        if locked { "set" } else { "clear" }
    );
    out.push(("svm", Detection::with_detail(status, SRC, detail.clone())));
    out.push(("svm_runtime", Detection::with_detail(status, SRC, detail)));
}

fn memory_encryption(msr: &dyn MsrAccess, out: &mut Findings) {
    if let Ok(value) = read(msr, MSR_AMD64_SYSCFG) {
        out.push((
            "sme_active",
            Detection::with_detail(
                if bit(value, 23) {
                    Status::Enabled
                } else {
                    Status::Disabled
                },
                SRC,
                format!(
                    "SYSCFG={value:#x}; memory-encryption bit {}",
                    if bit(value, 23) { "set" } else { "clear" }
                ),
            ),
        ));
    }
    if let Ok(value) = read(msr, MSR_AMD64_SEV) {
        for (id, position, label) in [
            ("sev", 0, "SEV"),
            ("sev_es", 1, "SEV-ES"),
            ("sev_snp", 2, "SEV-SNP"),
        ] {
            out.push((
                id,
                Detection::with_detail(
                    if bit(value, position) {
                        Status::Enabled
                    } else {
                        Status::Disabled
                    },
                    SRC,
                    format!(
                        "SEV_STATUS={value:#x}; {label} {}",
                        if bit(value, position) {
                            "active"
                        } else {
                            "inactive"
                        }
                    ),
                ),
            ));
        }
    }
}

fn values(msr: &dyn MsrAccess, out: &mut Findings) {
    if let Ok(value) = read(msr, MSR_K7_HWCR) {
        out.push((
            "hwcr",
            Detection::with_detail(Status::Present, SRC, format!("HWCR={value:#018x}")),
        ));
    }
    if let Ok(value) = read(msr, MSR_AMD_PSTATE_STATUS) {
        out.push((
            "pstate_status",
            Detection::with_detail(
                Status::Present,
                SRC,
                format!("hardware P-state P{} (MSR={value:#x})", value & 0x7),
            ),
        ));
    }
}

#[cfg(target_arch = "x86_64")]
fn is_amd_cpu() -> bool {
    use core::arch::x86_64::__cpuid;
    let result = __cpuid(0);
    let mut bytes = Vec::with_capacity(12);
    for word in [result.ebx, result.edx, result.ecx] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes == b"AuthenticAMD" || bytes == b"HygonGenuine"
}
#[cfg(not(target_arch = "x86_64"))]
fn is_amd_cpu() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn amd_register_numbers_are_extended_range() {
        for register in [
            MSR_AMD64_SYSCFG,
            MSR_K7_HWCR,
            MSR_AMD_PSTATE_STATUS,
            MSR_VM_CR,
            MSR_AMD64_SEV,
        ] {
            assert!(register >= 0xc000_0000);
        }
    }
}
