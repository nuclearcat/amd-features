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
    fn link(mut self, path: &str, target: &str) -> Self {
        self.links.insert(path.into(), target.into());
        self
    }
    fn device(mut self, path: &str) -> Self {
        self.openable.insert(path.into());
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
    assert_eq!(status(&partial, "dgpu"), Status::Unknown);
    let empty = PciProbe
        .detect(&context(
            MemoryReader::default().dir("/sys/bus/pci/devices", &[]),
        ))
        .unwrap();
    assert_eq!(status(&empty, "igpu"), Status::Absent);
    assert_eq!(status(&empty, "dgpu"), Status::Absent);
    assert_eq!(status(&empty, "rebar"), Status::Absent);
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

fn pci_gpu(reader: MemoryReader, bdf: &str, device: &str, class: &str) -> MemoryReader {
    let path = format!("/sys/bus/pci/devices/{bdf}");
    reader
        .file(&format!("{path}/vendor"), "0x1002")
        .file(&format!("{path}/device"), device)
        .file(&format!("{path}/class"), class)
        .link(&format!("{path}/driver"), "/sys/bus/pci/drivers/amdgpu")
}

#[test]
fn discrete_gpu_is_not_reported_as_integrated() {
    let path = "/sys/bus/pci/devices/0000:03:00.0";
    let reader = pci_gpu(
        MemoryReader::default().dir("/sys/bus/pci/devices", &["0000:03:00.0"]),
        "0000:03:00.0",
        "0x744c",
        "0x030000",
    )
    .file(&format!("{path}/mem_info_vram_total"), "17179869184")
    .file(&format!("{path}/mem_info_vis_vram_total"), "17179869184")
    .file(&format!("{path}/mem_info_gtt_total"), "4294967296")
    .file(&format!("{path}/current_link_speed"), "16.0 GT/s PCIe")
    .file(&format!("{path}/current_link_width"), "16")
    .file(&format!("{path}/board_info"), "type : cem")
    .file(
        "/sys/kernel/debug/dri/0000:03:00.0/amdgpu_firmware_info",
        "VCN feature version: 0, fw version: 0x0511001b\n",
    )
    .device("/dev/kfd")
    .dir("/sys/class/kfd/kfd/topology/nodes", &["1"])
    .file(
        "/sys/class/kfd/kfd/topology/nodes/1/properties",
        "cpu_cores_count 0\nsimd_count 96\ndevice_id 29772\ngfx_target_version 110000\nmax_engine_clk_fcompute 2500\nlocation_id 768\n",
    );
    let findings = PciProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "dgpu"), Status::Enabled);
    assert_eq!(status(&findings, "igpu"), Status::Absent);
    assert_eq!(status(&findings, "rebar"), Status::Enabled);
    assert_eq!(status(&findings, "vcn"), Status::Enabled);
    assert_eq!(status(&findings, "rocm"), Status::Enabled);
    let dgpu = findings.iter().find(|(id, _)| *id == "dgpu").unwrap();
    let detail = dgpu.1.detail.as_deref().unwrap();
    assert!(detail.contains("discrete"));
    assert!(detail.contains("16 GiB"));
    assert!(detail.contains("PCIe 16.0 GT/s PCIe x16"));
    let vram = findings.iter().find(|(id, _)| *id == "gpu_vram").unwrap();
    assert!(vram
        .1
        .detail
        .as_deref()
        .unwrap()
        .contains("dGPU 16 GiB VRAM"));
    let rebar = findings.iter().find(|(id, _)| *id == "rebar").unwrap();
    assert!(rebar.1.detail.as_deref().unwrap().contains("ReBAR/SAM"));
}

#[test]
fn raphael_igpu_is_not_a_discrete_card() {
    let path = "/sys/bus/pci/devices/0000:0c:00.0";
    let reader = pci_gpu(
        MemoryReader::default().dir("/sys/bus/pci/devices", &["0000:0c:00.0"]),
        "0000:0c:00.0",
        "0x164e",
        "0x030000",
    )
    .file(&format!("{path}/mem_info_vram_total"), "536870912")
    .file(&format!("{path}/mem_info_vis_vram_total"), "536870912")
    .file(&format!("{path}/mem_info_gtt_total"), "17179869184")
    .file(&format!("{path}/vbios_version"), "113-RAPHAEL-001")
    .file(
        "/sys/kernel/debug/dri/0000:0c:00.0/amdgpu_firmware_info",
        "VCN feature version: 0\nJPEG feature version: 0\n",
    );
    let findings = PciProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "igpu"), Status::Enabled);
    assert_eq!(status(&findings, "dgpu"), Status::Absent);
    assert_eq!(status(&findings, "rebar"), Status::Absent);
    assert_eq!(status(&findings, "vcn"), Status::Enabled);
    let igpu = findings.iter().find(|(id, _)| *id == "igpu").unwrap();
    let detail = igpu.1.detail.as_deref().unwrap();
    assert!(detail.contains("Raphael"));
    assert!(detail.contains("integrated"));
    assert!(detail.contains("VBIOS"));
    let vram = findings.iter().find(|(id, _)| *id == "gpu_vram").unwrap();
    assert!(vram.1.detail.as_deref().unwrap().contains("iGPU"));
}

#[test]
fn rebar_disabled_when_only_256mib_is_visible() {
    let path = "/sys/bus/pci/devices/0000:03:00.0";
    let reader = pci_gpu(
        MemoryReader::default().dir("/sys/bus/pci/devices", &["0000:03:00.0"]),
        "0000:03:00.0",
        "0x744c",
        "0x030000",
    )
    .file(&format!("{path}/mem_info_vram_total"), "17179869184")
    .file(&format!("{path}/mem_info_vis_vram_total"), "268435456")
    .file(&format!("{path}/board_info"), "type : cem");
    let findings = PciProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "dgpu"), Status::Enabled);
    assert_eq!(status(&findings, "rebar"), Status::Disabled);
    let rebar = findings.iter().find(|(id, _)| *id == "rebar").unwrap();
    assert!(rebar
        .1
        .detail
        .as_deref()
        .unwrap()
        .contains("256 MiB aperture"));
}

#[test]
fn kfd_cpu_cores_classify_an_unknown_id_as_igpu() {
    let reader = pci_gpu(
        MemoryReader::default().dir("/sys/bus/pci/devices", &["0000:c1:00.0"]),
        "0000:c1:00.0",
        "0xabcd",
        "0x030000",
    )
    .dir("/sys/class/kfd/kfd/topology/nodes", &["1"])
    .file(
        "/sys/class/kfd/kfd/topology/nodes/1/properties",
        "cpu_cores_count 12\nsimd_count 16\ndevice_id 43981\ngfx_target_version 110500\nlocation_id 49408\n",
    );
    let findings = PciProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "igpu"), Status::Enabled);
    assert_eq!(status(&findings, "dgpu"), Status::Absent);
    let igpu = findings.iter().find(|(id, _)| *id == "igpu").unwrap();
    assert!(igpu.1.detail.as_deref().unwrap().contains("gfx1150"));
}

fn type17_dimm(size_mb: u16, mem_type: u8, speed: u16) -> Vec<u8> {
    type17_dimm_speeds(size_mb, mem_type, speed, None)
}

fn type17_dimm_speeds(size_mb: u16, mem_type: u8, rated: u16, configured: Option<u16>) -> Vec<u8> {
    let len = if configured.is_some() { 0x22 } else { 0x18 };
    let mut formatted = vec![0; len];
    formatted[0] = 17;
    formatted[1] = len as u8;
    formatted[0x0c..0x0e].copy_from_slice(&size_mb.to_le_bytes());
    formatted[0x12] = mem_type;
    formatted[0x15..0x17].copy_from_slice(&rated.to_le_bytes());
    if let Some(configured) = configured {
        formatted[0x20..0x22].copy_from_slice(&configured.to_le_bytes());
    }
    let mut buf = formatted;
    buf.extend_from_slice(&[0, 0, 127, 4, 0, 0, 0, 0]);
    buf
}

#[test]
fn boost_clocks_show_asymmetric_ccd_range() {
    let reader = MemoryReader::default()
        .dir("/sys/devices/system/cpu", &["cpu0", "cpu8"])
        .file(
            "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq",
            "400000",
        )
        .file(
            "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
            "5750000",
        )
        .file(
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
            "5500000",
        )
        .file(
            "/sys/devices/system/cpu/cpu8/cpufreq/cpuinfo_min_freq",
            "400000",
        )
        .file(
            "/sys/devices/system/cpu/cpu8/cpufreq/cpuinfo_max_freq",
            "4200000",
        )
        .file("/sys/devices/system/cpu/cpufreq/boost", "1");
    let findings = SysfsProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "cpu_freq"), Status::Present);
    let detail = findings
        .iter()
        .find(|(id, _)| *id == "cpu_freq")
        .unwrap()
        .1
        .detail
        .as_deref()
        .unwrap();
    assert!(detail.contains("asymmetric CCDs"));
    assert!(detail.contains("4200 MHz"));
    assert!(detail.contains("5750 MHz"));
    assert!(detail.contains("boost=on"));
}

#[test]
fn package_power_maps_rapl_limits_to_tdp_and_ppt() {
    let path = "/sys/class/powercap/intel-rapl:0";
    let reader = MemoryReader::default()
        .dir("/sys/class/powercap", &["intel-rapl:0"])
        .file(&format!("{path}/name"), "package-0")
        .file(&format!("{path}/constraint_0_name"), "long_term")
        .file(&format!("{path}/constraint_0_power_limit_uw"), "142000000")
        .file(&format!("{path}/constraint_1_name"), "short_term")
        .file(&format!("{path}/constraint_1_power_limit_uw"), "230000000")
        .dir("/sys/class/hwmon", &["hwmon0"])
        .file("/sys/class/hwmon/hwmon0/name", "zenpower")
        .file("/sys/class/hwmon/hwmon0/power1_label", "PPT")
        .file("/sys/class/hwmon/hwmon0/power1_input", "61200000");
    let findings = SysfsProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "package_power"), Status::Present);
    let detail = findings
        .iter()
        .find(|(id, _)| *id == "package_power")
        .unwrap()
        .1
        .detail
        .as_deref()
        .unwrap();
    assert!(detail.contains("TDP/long_term 142 W"));
    assert!(detail.contains("PPT/short_term 230 W"));
    assert!(detail.contains("hwmon PPT 61.2 W"));
}

#[test]
fn vcache_detects_asymmetric_96mib_ccd() {
    let reader = MemoryReader::default()
        .file(
            "/proc/cpuinfo",
            "model name : AMD Ryzen 9 7950X3D 16-Core Processor\n",
        )
        .dir("/sys/devices/system/cpu", &["cpu0", "cpu8"])
        .dir("/sys/devices/system/cpu/cpu0/cache", &["index3"])
        .file("/sys/devices/system/cpu/cpu0/cache/index3/level", "3")
        .file("/sys/devices/system/cpu/cpu0/cache/index3/size", "98304K")
        .file(
            "/sys/devices/system/cpu/cpu0/cache/index3/shared_cpu_list",
            "0-7",
        )
        .dir("/sys/devices/system/cpu/cpu8/cache", &["index3"])
        .file("/sys/devices/system/cpu/cpu8/cache/index3/level", "3")
        .file("/sys/devices/system/cpu/cpu8/cache/index3/size", "32768K")
        .file(
            "/sys/devices/system/cpu/cpu8/cache/index3/shared_cpu_list",
            "8-15",
        )
        .dir("/sys/bus/platform/drivers/amd_x3d_vcache", &["AMDI0101:00"])
        .file(
            "/sys/bus/platform/drivers/amd_x3d_vcache/AMDI0101:00/amd_x3d_mode",
            "frequency",
        );
    let findings = SysfsProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "vcache"), Status::Enabled);
    let detail = findings
        .iter()
        .find(|(id, _)| *id == "vcache")
        .unwrap()
        .1
        .detail
        .as_deref()
        .unwrap();
    assert!(detail.contains("96 MiB"));
    assert!(detail.contains("32 MiB"));
    assert!(detail.contains("asymmetric CCDs"));
    assert!(detail.contains("amd_x3d_vcache mode=frequency"));
}

#[test]
fn fabric_shows_fclk_and_dimm_data_rate() {
    let mut dmi = type17_dimm(16384, 0x22, 6400);
    dmi.extend_from_slice(&[127, 4, 0, 0, 0, 0]);
    let reader = MemoryReader::default()
        .dir("/sys/class/hwmon", &["hwmon1"])
        .file("/sys/class/hwmon/hwmon1/name", "zenpower")
        .file("/sys/class/hwmon/hwmon1/freq1_label", "FCLK")
        .file("/sys/class/hwmon/hwmon1/freq1_input", "2000000000")
        .file("/sys/class/hwmon/hwmon1/freq2_label", "UCLK")
        .file("/sys/class/hwmon/hwmon1/freq2_input", "3200000000")
        .file("/sys/firmware/dmi/tables/DMI", dmi);
    let findings = SysfsProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "fabric"), Status::Present);
    let detail = findings
        .iter()
        .find(|(id, _)| *id == "fabric")
        .unwrap()
        .1
        .detail
        .as_deref()
        .unwrap();
    assert!(detail.contains("FCLK 2000 MHz"));
    assert!(detail.contains("UCLK 3200 MHz"));
    assert!(detail.contains("6400 MT/s"));
}

#[test]
fn installed_memory_shows_operating_speed() {
    let findings = DmiProbe
        .detect(&context(MemoryReader::default().file(
            "/sys/firmware/dmi/tables/DMI",
            type17_dimm_speeds(16384, 0x22, 6400, Some(6000)),
        )))
        .unwrap();
    assert_eq!(status(&findings, "memory_dimms"), Status::Present);
    let detail = findings
        .iter()
        .find(|(id, _)| *id == "memory_dimms")
        .unwrap()
        .1
        .detail
        .as_deref()
        .unwrap();
    assert!(detail.contains("DDR5-6400"));
    assert!(detail.contains("operating 6000 MT/s"));
}

fn ddr5_expo_spd(jedec_ps: u16, profile_ps: u16) -> Vec<u8> {
    let mut spd = vec![0; 1024];
    spd[2] = 0x12;
    spd[20..22].copy_from_slice(&jedec_ps.to_le_bytes());
    spd[0x280..0x284].copy_from_slice(b"EXPO");
    spd[0x285] = 0x01;
    spd[0x280 + 0x0a + 4..0x280 + 0x0a + 6].copy_from_slice(&profile_ps.to_le_bytes());
    spd
}

#[test]
fn xmp_expo_matches_firmware_operating_speed() {
    let reader = MemoryReader::default()
        .dir("/sys/bus/i2c/devices", &["1-0050"])
        .file(
            "/sys/bus/i2c/devices/1-0050/eeprom",
            ddr5_expo_spd(417, 333),
        )
        .file(
            "/sys/firmware/dmi/tables/DMI",
            type17_dimm_speeds(16384, 0x22, 6400, Some(6000)),
        );
    let findings = SysfsProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "memory_xmp"), Status::Enabled);
    let detail = findings
        .iter()
        .find(|(id, _)| *id == "memory_xmp")
        .unwrap()
        .1
        .detail
        .as_deref()
        .unwrap();
    assert!(detail.contains("JEDEC 4800"));
    assert!(detail.contains("EXPO1 6000 MT/s"));
    assert!(detail.contains("operating 6000 MT/s"));
    assert!(detail.contains("matches XMP/EXPO"));
}

#[test]
fn jedec_only_spd_is_absent_xmp() {
    let mut spd = vec![0; 1024];
    spd[2] = 0x12;
    spd[20..22].copy_from_slice(&417u16.to_le_bytes());
    let reader = MemoryReader::default()
        .dir("/sys/bus/i2c/devices", &["1-0050"])
        .file("/sys/bus/i2c/devices/1-0050/eeprom", spd);
    let findings = SysfsProbe.detect(&context(reader)).unwrap();
    assert_eq!(status(&findings, "memory_xmp"), Status::Absent);
    let detail = findings
        .iter()
        .find(|(id, _)| *id == "memory_xmp")
        .unwrap()
        .1
        .detail
        .as_deref()
        .unwrap();
    assert!(detail.contains("JEDEC 4800"));
}
