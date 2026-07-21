//! End-to-end tests over the public library API. These are hardware-independent
//! except `real_probes_do_not_panic`, which just exercises the read-only probes.

use std::collections::HashMap;

use amd_features::catalog;
use amd_features::expectations::{Attention, ExpectationLevel};
use amd_features::model::{Category, Detection, Privilege, Status};
use amd_features::probes::cpuid::Identity;
use amd_features::probes::{self, Context};
use amd_features::report::Report;

/// Every catalog feature id must be unique — probes key detections by id, so a
/// collision would silently merge two features.
#[test]
fn catalog_ids_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for f in catalog::FEATURES {
        assert!(!f.id.is_empty(), "empty id for {}", f.name);
        assert!(seen.insert(f.id), "duplicate feature id: {}", f.id);
    }
}

/// Every catalog category is covered by the display order, and every feature lands
/// in exactly one category bucket.
#[test]
fn build_covers_every_feature() {
    let report = Report::build(HashMap::new(), None, None, Privilege::User);
    assert_eq!(report.categories.len(), Category::ORDER.len());
    let total: usize = report.categories.iter().map(|c| c.features.len()).sum();
    assert_eq!(total, catalog::FEATURES.len());
}

/// With no detections, every feature is Unknown.
#[test]
fn empty_results_are_all_unknown() {
    let report = Report::build(HashMap::new(), None, None, Privilege::User);
    for cat in &report.categories {
        for f in &cat.features {
            assert_eq!(f.status, Status::Unknown, "{} should be unknown", f.id);
            assert!(f.detections.is_empty());
        }
    }
}

/// The headline status is the highest-ranked detection: a firmware/OS `Disabled`
/// outranks a silicon `Present`. This is the core aggregation contract.
#[test]
fn headline_prefers_higher_rank() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "smt",
        vec![
            Detection::new(Status::Present, "cpuid"),
            Detection::new(Status::Disabled, "linux-sysfs"),
        ],
    );
    let report = Report::build(results, None, None, Privilege::User);
    let smt = find(&report, "smt");
    assert_eq!(smt.status, Status::Disabled);
    assert_eq!(smt.detections.len(), 2);
}

/// Detections keyed by an unknown id are rejected as programmer errors.
#[test]
fn unknown_ids_are_rejected() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "not_a_real_feature",
        vec![Detection::new(Status::Present, "cpuid")],
    );
    assert!(Report::try_build(results, None, None, Privilege::User).is_err());
}

#[test]
fn enabled_disabled_conflict_is_unknown_and_noted() {
    let mut results = HashMap::new();
    results.insert(
        "cpb",
        vec![
            Detection::new(Status::Enabled, "a"),
            Detection::new(Status::Disabled, "b"),
        ],
    );
    let report = Report::try_build(results, None, None, Privilege::User).unwrap();
    assert_eq!(find(&report, "cpb").status, Status::Unknown);
    assert!(report
        .notes
        .iter()
        .any(|note| note.contains("conflicting enabled and disabled")));
}

/// CPUID-present + kernel-flag-absent must raise a disparity note.
#[test]
fn disparity_cpuid_present_kernel_absent() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "aes",
        vec![
            Detection::new(Status::Present, "cpuid"),
            Detection::new(Status::Absent, "procfs"),
        ],
    );
    let report = Report::build(results, None, None, Privilege::User);
    assert_eq!(report.notes.len(), 1);
    assert!(
        report.notes[0].contains("AES-NI"),
        "note was: {}",
        report.notes[0]
    );
}

/// CPUID-absent + kernel-flag-present points at a decode gap in our probe.
#[test]
fn disparity_kernel_present_cpuid_absent() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "aes",
        vec![
            Detection::new(Status::Absent, "cpuid"),
            Detection::new(Status::Present, "procfs"),
        ],
    );
    let report = Report::build(results, None, None, Privilege::User);
    assert_eq!(report.notes.len(), 1);
    assert!(
        report.notes[0].contains("decode gap"),
        "note was: {}",
        report.notes[0]
    );
}

/// Agreement between CPUID and the kernel must produce no note.
#[test]
fn no_disparity_when_sources_agree() {
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    results.insert(
        "aes",
        vec![
            Detection::new(Status::Present, "cpuid"),
            Detection::new(Status::Present, "procfs"),
        ],
    );
    let report = Report::build(results, None, None, Privilege::User);
    assert!(report.notes.is_empty());
}

/// Kernel-flag names in the catalog must be well-formed (lowercase, no whitespace).
#[test]
fn cpuinfo_flags_are_well_formed() {
    for f in catalog::FEATURES {
        if let Some(flag) = f.cpuinfo_flag {
            assert!(!flag.is_empty(), "{} has empty flag", f.id);
            assert!(
                flag.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "malformed flag {flag:?} for {}",
                f.id
            );
        }
    }
}

/// Vulnerability and MSR value features must be flagged for inline-detail rendering.
#[test]
fn value_features_are_inline() {
    for id in [
        "meltdown",
        "spectre_v2",
        "hwcr",
        "svm_runtime",
        "memory_dimms",
    ] {
        let f = catalog::find(id).unwrap_or_else(|| panic!("{id} missing"));
        assert!(f.inline_detail, "{id} should be inline_detail");
    }
    // A plain capability must not be.
    assert!(!catalog::find("avx2").unwrap().inline_detail);
}

/// Boolean capability features must never carry a `/proc/cpuinfo` flag *and* be a value
/// feature (would double-render). Sanity check on catalog consistency.
#[test]
fn inline_features_have_no_kernel_flag() {
    for f in catalog::FEATURES {
        if f.inline_detail {
            assert!(
                f.cpuinfo_flag.is_none(),
                "{} is inline yet has a flag",
                f.id
            );
        }
    }
}

#[test]
fn json_output_is_produced() {
    let report = Report::build(HashMap::new(), None, None, Privilege::Root);
    let json = report.to_json();
    assert!(json.contains("\"tool\": \"amd-features\""));
    assert!(json.contains("\"privilege\": \"root\""));
}

#[test]
fn text_output_includes_purpose_column() {
    let mut results = HashMap::new();
    results.insert("aes", vec![Detection::new(Status::Present, "cpuid")]);
    let report = Report::build(results, None, None, Privilege::User);
    let text = report.render_text(amd_features::report::TextOptions {
        color: false,
        verbose: false,
        hide_absent: true,
    });
    assert!(text.contains("Purpose / notable instructions"));
    assert!(text.contains("AES round and key-generation instructions"));
}

#[test]
fn expected_absence_is_red_and_visible_without_all() {
    let mut results = HashMap::new();
    results.insert("avx512f", vec![Detection::new(Status::Absent, "cpuid")]);
    let report = Report::build(results, Some(zen5_identity()), None, Privilege::User);
    let feature = find(&report, "avx512f");
    assert_eq!(feature.attention, Some(Attention::Critical));
    assert_eq!(
        feature.expectation.unwrap().level,
        ExpectationLevel::Expected
    );

    let plain = report.render_text(amd_features::report::TextOptions {
        color: false,
        verbose: false,
        hide_absent: true,
    });
    assert!(plain.contains("! AVX-512F"));
    assert!(plain.contains("! red: expected for this hardware class"));

    let colored = report.render_text(amd_features::report::TextOptions {
        color: true,
        verbose: false,
        hide_absent: true,
    });
    assert!(colored.contains("\x1b[31m!\x1b[0m"));
    assert!(report.to_json().contains("\"attention\": \"critical\""));
}

#[test]
fn optional_class_feature_absence_is_yellow() {
    let mut results = HashMap::new();
    results.insert("avx512fp16", vec![Detection::new(Status::Absent, "cpuid")]);
    let report = Report::build(results, Some(zen5_identity()), None, Privilege::User);
    let feature = find(&report, "avx512fp16");
    assert_eq!(feature.attention, Some(Attention::Warning));
    assert_eq!(
        feature.expectation.unwrap().level,
        ExpectationLevel::Available
    );
    let colored = report.render_text(amd_features::report::TextOptions {
        color: true,
        verbose: false,
        hide_absent: true,
    });
    assert!(colored.contains("\x1b[33m!\x1b[0m"));
}

#[test]
fn unknown_state_does_not_claim_a_feature_is_missing() {
    let mut results = HashMap::new();
    results.insert("avx512f", vec![Detection::new(Status::Unknown, "cpuid")]);
    let report = Report::build(results, Some(zen5_identity()), None, Privilege::User);
    assert_eq!(find(&report, "avx512f").attention, None);
}

/// The real probes are read-only; running them must never panic regardless of host.
#[test]
fn real_probes_do_not_panic() {
    let ctx = Context::detect();
    let mut results: HashMap<&'static str, Vec<Detection>> = HashMap::new();
    for probe in probes::all() {
        let declared = probe.feature_ids();
        let findings = probe.detect(&ctx).expect("probe should degrade gracefully");
        let found: std::collections::HashSet<_> = findings.iter().map(|(id, _)| *id).collect();
        for id in &declared {
            assert!(
                catalog::find(id).is_some(),
                "{} declares unknown id {id}",
                probe.name()
            );
            assert!(
                found.contains(id),
                "{} did not report declared id {id}",
                probe.name()
            );
        }
        for (id, det) in findings {
            assert!(
                declared.contains(&id),
                "{} emitted undeclared id {id}",
                probe.name()
            );
            assert_eq!(det.source, probe.name(), "source mismatch for {id}");
            results.entry(id).or_default().push(det);
        }
    }
    let report = Report::build(
        results,
        probes::cpuid::identity(),
        probes::firmware::system_info(),
        ctx.privilege,
    );
    // Text rendering must also not panic.
    let _ = report.render_text(amd_features::report::TextOptions {
        color: false,
        verbose: true,
        hide_absent: false,
    });
}

fn find<'a>(report: &'a Report, id: &str) -> &'a amd_features::report::FeatureReport {
    report
        .categories
        .iter()
        .flat_map(|c| &c.features)
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("feature {id} not found"))
}

fn zen5_identity() -> Identity {
    Identity {
        vendor: "AuthenticAMD".into(),
        brand: "AMD Ryzen test processor".into(),
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
