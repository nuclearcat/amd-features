# amd-features

`amd-features` is a modular, read-only detector for AMD processors and platforms on
Linux/x86-64. It reports silicon support, firmware enablement, and operating-system
state separately instead of collapsing them into one ambiguous yes/no answer.

## What it detects

The catalog covers AMD and common x86 features across instruction sets, speculation
controls, Secure Memory Encryption (SME), Secure Encrypted Virtualization
(SEV/SEV-ES/SEV-SNP), AMD-V/SVM and nested paging, CPPC/Core Performance Boost,
topology, memory-channel capability, Instruction-Based Sampling, Platform QoS, AMD
PCI devices and motherboard chipsets, ACPI, UEFI, SMBIOS memory, and kernel
vulnerability mitigations.

Ten independent probes provide traceable evidence:

- **cpuid** reads standard and AMD extended leaves on every eligible logical CPU,
  pinned one CPU at a time. It reports asymmetric feature exposure, the processor
  signature and brand, microcode revision, and a family/model lookup. Shared
  model ranges (for example Genoa vs Storm Peak) are disambiguated from the
  processor brand string; otherwise the report keeps a slash-separated name.
- **procfs** cross-checks CPUID against every matching `/proc/cpuinfo` flag.
- **linux-sysfs** reports SMT and KVM state, `amd_pstate`, boost clocks, PPT/TDP,
  3D V-Cache, Infinity Fabric/memory data rate, CPU idle, AMD energy/hwmon drivers,
  TPM, resctrl/PQoS, Bluetooth, and IPMI.
- **linux-vuln** preserves the kernel's mitigation text from
  `/sys/devices/system/cpu/vulnerabilities`.
- **msr** performs read-only AMD MSR queries for VM_CR, SYSCFG, SEV status, HWCR,
  and current hardware P-state. It never writes a register.
- **pci** inventories AMD/ATI PCI functions including integrated vs discrete Radeon
  GPUs (VRAM, GTT/UMA, ReBAR/SAM, VCN/UVD, ROCm/KFD), Ryzen AI/XDNA, PSP/CCP,
  chipset bridges, audio, SMBus, USB, SATA, NVMe, and networking.
- **acpi** detects AMD-Vi through IVRS/IOMMU state plus LPIT, NFIT, CEDT, HMAT,
  HPET, SRAT, WSMT, and TPM2.
- **efi** reports UEFI boot, Secure Boot, Setup Mode, and ESRT.
- **dmi** reports board/BIOS identity, memory ECC capability, and populated DIMMs.
- **memory-topology** infers the maximum channels per CPU socket from the AMD product
  and board class, and separately reports EDAC controller visibility. It does not claim
  that the maximum channel count is populated or active when Linux exposes no telemetry.

Chipset reporting prefers an exact chipset token from the DMI board name and corroborates
it with AMD Promontory PCI functions. When only shared PCI IDs are available, it reports
the chipset family and explicitly leaves the retail SKU unknown.

Missing, inaccessible, malformed, or partially enumerated authoritative interfaces are
reported as `unknown`. `absent` is only used when the relevant parent interface was
successfully inspected. On a non-AMD CPU, vendor-specific CPUID and MSR findings are
reported as unknown rather than mis-decoded.

## Class-aware attention

For recognized Zen-family processors, the report compares detections with a conservative
generation profile without changing the underlying detection status:

- **Red `!`** means a baseline capability expected for that hardware class is reported
  absent or disabled. For example, AVX-512 foundation support missing on Zen 4/5 is
  highlighted even when `--all` was not requested.
- **Yellow `!`** means the class can provide the capability, but availability depends on
  the product, firmware settings, kernel support, or runtime configuration.

Unknown results are not treated as missing. The JSON report exposes separate
`expectation` and `attention` fields so automation can distinguish measured state from
the class-based assessment.

## Build and run

```sh
cargo build --release
./target/release/amd-features
./target/release/amd-features --json
./target/release/amd-features --all --verbose
sudo ./target/release/amd-features --load-msr-module
```

Options: `--json/-j`, `--verbose/-v`, `--all/-a`, `--no-color`,
`--load-msr-module`, `--help/-h`, and `--version/-V`.

The program is non-mutating by default. `--load-msr-module` permits one `modprobe msr`
attempt only when the effective UID is root and `/dev/cpu/0/msr` is missing. Root does
not guarantee access in containers, under kernel lockdown, or with restrictive device
cgroups.

## Architecture

```text
model      shared statuses, detections, categories, and feature metadata
catalog    static registry of AMD and common x86 features
cpu_db     AMD family/model classification, with brand disambiguation for shared ranges
probes/    one read-only module per detection mechanism
report     aggregation plus text and JSON rendering
```

Each detection includes a status, source, and evidence detail such as
`CPUID.8000000AH:EDX[0]`. Conflicting enabled and disabled findings produce an
`unknown` headline while retaining both findings for diagnosis.

## License and trademarks

Licensed under MIT OR Apache-2.0.

This independent project is not affiliated with or endorsed by Advanced Micro Devices,
Inc. AMD names are used only to identify compatible processors and technologies. See
[`TRADEMARKS.md`](TRADEMARKS.md).
