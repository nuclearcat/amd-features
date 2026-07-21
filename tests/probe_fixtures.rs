use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use amd_features::model::{Privilege, Status};
use amd_features::probes::acpi::AcpiProbe;
use amd_features::probes::firmware::{DmiProbe, EfiProbe};
use amd_features::probes::memory::MemoryProbe;
use amd_features::probes::msr::MsrProbe;
use amd_features::probes::pci::PciProbe;
use amd_features::probes::procfs::ProcfsProbe;
use amd_features::probes::sysfs::SysfsProbe;
use amd_features::probes::{
    Context, ContextOptions, DirEntry, MsrAccess, Probe, SystemMetadata, SystemReader,
};

#[derive(Default)]
struct MemoryReader {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: HashMap<PathBuf, Vec<Result<String, io::ErrorKind>>>,
    denied: HashSet<PathBuf>,
    links: HashMap<PathBuf, PathBuf>,
    openable: HashSet<PathBuf>,
}

impl MemoryReader {
    fn file(mut self, path: &str, value: impl AsRef<[u8]>) -> Self {
        self.files.insert(path.into(), value.as_ref().to_vec());
        self
    }
    fn dir(mut self, path: &str, entries: &[&str]) -> Self {
        self.dirs.insert(
            path.into(),
            entries.iter().map(|name| Ok((*name).to_string())).collect(),
        );
        self
    }
    fn partial_dir(mut self, path: &str) -> Self {
        self.dirs
            .insert(path.into(), vec![Err(io::ErrorKind::PermissionDenied)]);
        self
    }
}

impl SystemReader for MemoryReader {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<io::Result<DirEntry>>> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.dirs
            .get(path)
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| match entry {
                        Ok(name) => Ok(DirEntry {
                            path: path.join(name),
                            file_name: name.clone(),
                        }),
                        Err(kind) => Err(io::Error::from(*kind)),
                    })
                    .collect()
            })
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    fn metadata(&self, path: &Path) -> io::Result<SystemMetadata> {
        if self.denied.contains(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        if self.dirs.contains_key(path) {
            Ok(SystemMetadata { is_dir: true })
        } else if self.files.contains_key(path) || self.openable.contains(path) {
            Ok(SystemMetadata { is_dir: false })
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        self.links
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    fn open_device(&self, path: &Path, _read_write: bool) -> io::Result<()> {
        if self.openable.contains(path) {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
}

#[derive(Default)]
struct FakeMsr {
    values: HashMap<u32, Result<u64, io::ErrorKind>>,
    loads: Mutex<usize>,
}

impl MsrAccess for FakeMsr {
    fn read(&self, _cpu: u32, register: u32) -> io::Result<u64> {
        self.values.get(&register).map_or_else(
            || Err(io::Error::from(io::ErrorKind::Other)),
            |value| match value {
                Ok(value) => Ok(*value),
                Err(kind) => Err(io::Error::from(*kind)),
            },
        )
    }
    fn load_module(&self) -> Result<(), String> {
        *self.loads.lock().unwrap() += 1;
        Ok(())
    }
}

fn context(reader: MemoryReader) -> Context {
    Context::new(
        Privilege::User,
        Arc::new(reader),
        Arc::new(FakeMsr::default()),
        ContextOptions::default(),
    )
}

fn status(findings: &amd_features::probes::Findings, id: &str) -> Status {
    findings
        .iter()
        .find(|(found, _)| *found == id)
        .unwrap_or_else(|| panic!("missing {id}"))
        .1
        .status
}

#[test]
fn acpi_unavailable_differs_from_inspected_and_absent() {
    let missing = AcpiProbe.detect(&context(MemoryReader::default())).unwrap();
    assert_eq!(status(&missing, "cxl"), Status::Unknown);
    let empty = AcpiProbe
        .detect(&context(
            MemoryReader::default().dir("/sys/firmware/acpi/tables", &[]),
        ))
        .unwrap();
    assert_eq!(status(&empty, "cxl"), Status::Absent);
}

#[test]
fn partial_pci_enumeration_cannot_prove_absence() {
    let partial = PciProbe
        .detect(&context(
            MemoryReader::default().partial_dir("/sys/bus/pci/devices"),
        ))
        .unwrap();
    assert_eq!(status(&partial, "igpu"), Status::Unknown);
    let empty = PciProbe
        .detect(&context(
            MemoryReader::default().dir("/sys/bus/pci/devices", &[]),
        ))
        .unwrap();
    assert_eq!(status(&empty, "igpu"), Status::Absent);
}

#[test]
fn procfs_reports_asymmetric_flags_across_all_blocks() {
    let cpuinfo = "processor : 0\nflags : sse avx2\n\nprocessor : 1\nflags : sse\n";
    let findings = ProcfsProbe
        .detect(&context(
            MemoryReader::default().file("/proc/cpuinfo", cpuinfo),
        ))
        .unwrap();
    let avx2 = findings.iter().find(|(id, _)| *id == "avx2").unwrap();
    assert_eq!(avx2.1.status, Status::Present);
    assert!(avx2.1.detail.as_deref().unwrap().contains("1/2 CPUs"));
    assert_eq!(status(&findings, "sse"), Status::Present);
}

#[test]
fn memory_channels_are_inferred_but_active_state_stays_explicit() {
    let cpuinfo = "processor : 0\nvendor_id : AuthenticAMD\ncpu family : 26\nmodel name : AMD Ryzen 7 9800X3D 8-Core Processor\nflags : sse\n";
    let reader = MemoryReader::default()
        .file("/proc/cpuinfo", cpuinfo)
        .file("/sys/class/dmi/id/board_name", "PRO X870-P WIFI")
        .dir("/sys/devices/system/edac/mc", &[]);
    let findings = MemoryProbe.detect(&context(reader)).unwrap();
    let channels = findings
        .iter()
        .find(|(id, _)| *id == "memory_channels")
        .unwrap();
    assert_eq!(channels.1.status, Status::Present);
    let detail = channels.1.detail.as_deref().unwrap();
    assert!(detail.contains("2 memory channel(s) per CPU socket"));
    assert!(detail.contains("active-channel telemetry unavailable"));
}

#[test]
fn chipset_combines_dmi_name_with_promontory_pci_evidence() {
    let path = "/sys/bus/pci/devices/0000:01:00.0";
    let reader = MemoryReader::default()
        .dir("/sys/bus/pci/devices", &["0000:01:00.0"])
        .file(&format!("{path}/vendor"), "0x1022")
        .file(&format!("{path}/device"), "0x43fc")
        .file(&format!("{path}/class"), "0x0c0330")
        .file("/sys/class/dmi/id/board_name", "PRO X870-P WIFI");
    let findings = PciProbe.detect(&context(reader)).unwrap();
    let chipset = findings.iter().find(|(id, _)| *id == "chipset").unwrap();
    assert_eq!(chipset.1.status, Status::Present);
    let detail = chipset.1.detail.as_deref().unwrap();
    assert!(detail.contains("AMD X870 chipset"));
    assert!(detail.contains("1022:43fc"));
}

#[test]
fn malformed_cpuinfo_is_unknown_not_absent() {
    let findings = ProcfsProbe
        .detect(&context(
            MemoryReader::default().file("/proc/cpuinfo", "processor : 0\n"),
        ))
        .unwrap();
    assert_eq!(status(&findings, "avx2"), Status::Unknown);
}

#[test]
fn missing_efi_interface_does_not_claim_legacy_bios() {
    let findings = EfiProbe.detect(&context(MemoryReader::default())).unwrap();
    assert_eq!(status(&findings, "uefi_boot"), Status::Unknown);
}

#[test]
fn confirmed_efi_with_missing_esrt_is_absent() {
    let reader = MemoryReader::default()
        .dir("/sys/firmware/efi", &[])
        .dir("/sys/firmware/efi/efivars", &[]);
    let findings = EfiProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "uefi_boot"), Status::Enabled);
    assert_eq!(status(&findings, "esrt"), Status::Absent);
}

fn smbios_type16(ecc: u8) -> Vec<u8> {
    let mut data = vec![0; 0x0f];
    data[0] = 16;
    data[1] = 0x0f;
    data[6] = ecc;
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(&[127, 4, 0, 0, 0, 0]);
    data
}

#[test]
fn smbios_ecc_none_and_unknown_are_distinct() {
    let none = DmiProbe
        .detect(&context(
            MemoryReader::default().file("/sys/firmware/dmi/tables/DMI", smbios_type16(3)),
        ))
        .unwrap();
    assert_eq!(status(&none, "memory_ecc"), Status::Absent);
    let unknown = DmiProbe
        .detect(&context(
            MemoryReader::default().file("/sys/firmware/dmi/tables/DMI", smbios_type16(2)),
        ))
        .unwrap();
    assert_eq!(status(&unknown, "memory_ecc"), Status::Unknown);
}

#[test]
fn amd_pstate_does_not_assert_cppc() {
    let reader = MemoryReader::default()
        .file(
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver",
            "amd-pstate-epp",
        )
        .file("/sys/devices/system/cpu/cpufreq/boost", "1");
    let findings = SysfsProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "amd_pstate"), Status::Enabled);
    assert!(!findings.iter().any(|(id, _)| *id == "cppc"));
}

#[test]
fn module_loading_requires_explicit_root_opt_in_and_runs_once() {
    let msr = Arc::new(FakeMsr::default());
    let no_opt = Context::new(
        Privilege::Root,
        Arc::new(MemoryReader::default()),
        msr.clone(),
        ContextOptions::default(),
    );
    MsrProbe.detect(&no_opt).unwrap();
    assert_eq!(*msr.loads.lock().unwrap(), 0);

    let user_opt = Context::new(
        Privilege::User,
        Arc::new(MemoryReader::default()),
        msr.clone(),
        ContextOptions {
            load_msr_module: true,
        },
    );
    MsrProbe.detect(&user_opt).unwrap();
    assert_eq!(*msr.loads.lock().unwrap(), 0);

    let root_opt = Context::new(
        Privilege::Root,
        Arc::new(MemoryReader::default()),
        msr.clone(),
        ContextOptions {
            load_msr_module: true,
        },
    );
    MsrProbe.detect(&root_opt).unwrap();
    MsrProbe.detect(&root_opt).unwrap();
    assert_eq!(*msr.loads.lock().unwrap(), 1);
}
