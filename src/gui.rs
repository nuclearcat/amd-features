//! Native, read-only feature explorer. Collection runs away from the UI thread.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use amd_features::model::{Category, Status};
use amd_features::probes::Context;
use amd_features::report::{self, FeatureReport, Report};
use eframe::egui::{self, Color32, RichText, Stroke, Ui};

const BACKGROUND: Color32 = Color32::from_rgb(13, 17, 25);
const SURFACE: Color32 = Color32::from_rgb(21, 27, 38);
const BORDER: Color32 = Color32::from_rgb(42, 51, 67);
const MUTED: Color32 = Color32::from_rgb(148, 161, 180);
const ACCENT: Color32 = Color32::from_rgb(255, 144, 94);
const GREEN: Color32 = Color32::from_rgb(103, 220, 173);
const CYAN: Color32 = Color32::from_rgb(113, 195, 236);

pub fn run(context: Context) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("AMD Features — System Observatory")
            .with_inner_size([1320.0, 900.0])
            .with_min_inner_size([880.0, 620.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "amd-features",
        options,
        Box::new(move |cc| {
            theme(&cc.egui_ctx);
            let mut app = Dashboard::new(context);
            app.refresh(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
}

fn theme(ctx: &egui::Context) {
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = BACKGROUND;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = BACKGROUND;
    style.visuals.selection.bg_fill = Color32::from_rgb(78, 51, 42);
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    style.visuals.widgets.inactive.bg_fill = SURFACE;
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(39, 48, 64);
    style.spacing.item_spacing = egui::vec2(10.0, 9.0);
    style.spacing.button_padding = egui::vec2(13.0, 9.0);
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    ctx.set_theme(egui::Theme::Dark);
    ctx.set_style_of(egui::Theme::Dark, style);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Overview,
    All,
    Category(Category),
}

struct Dashboard {
    context: Context,
    report: Option<Report>,
    pending: Option<Receiver<Result<Report, String>>>,
    error: Option<String>,
    updated: Option<Instant>,
    auto_refresh: bool,
    view: View,
    search: String,
    status: Option<Status>,
    attention_only: bool,
}

impl Dashboard {
    fn new(context: Context) -> Self {
        Self {
            context,
            report: None,
            pending: None,
            error: None,
            updated: None,
            auto_refresh: false,
            view: View::Overview,
            search: String::new(),
            status: None,
            attention_only: false,
        }
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        if self.pending.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let context = self.context.clone();
        let repaint = ctx.clone();
        match std::thread::Builder::new()
            .name("feature-probes".into())
            .spawn(move || {
                let result = report::collect(&context);
                let _ = sender.send(result);
                repaint.request_repaint();
            }) {
            Ok(_) => {
                self.pending = Some(receiver);
                self.error = None;
            }
            Err(error) => self.error = Some(format!("Cannot start refresh: {error}")),
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = &self.pending {
            match receiver.try_recv() {
                Ok(Ok(report)) => {
                    self.report = Some(report);
                    self.updated = Some(Instant::now());
                    self.error = None;
                    self.pending = None;
                }
                Ok(Err(error)) => {
                    self.error = Some(error);
                    self.pending = None;
                    self.auto_refresh = false;
                }
                Err(TryRecvError::Disconnected) => {
                    self.error =
                        Some("The probe worker stopped. You can retry with Refresh.".into());
                    self.pending = None;
                    self.auto_refresh = false;
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        if self.auto_refresh
            && self
                .updated
                .is_none_or(|time| time.elapsed() >= Duration::from_secs(5))
        {
            self.refresh(ctx);
        }
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn draw(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        egui::Panel::left("navigation").exact_size(238.0).resizable(false)
            .frame(egui::Frame::NONE.fill(SURFACE).inner_margin(20))
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("AMD / FEATURES").size(20.0).strong().color(ACCENT));
                ui.label(RichText::new("SYSTEM OBSERVATORY").size(10.0).color(MUTED));
                ui.add_space(28.0);
                nav(ui, &mut self.view, View::Overview, "Overview");
                nav(ui, &mut self.view, View::All, "All features");
                ui.add_space(18.0);
                ui.label(RichText::new("EXPLORE HARDWARE").size(10.0).color(MUTED));
                egui::ScrollArea::vertical().id_salt("navigation-scroll").show(ui, |ui| {
                    for &category in Category::ORDER {
                        nav(ui, &mut self.view, View::Category(category), short_category(category));
                    }
                    ui.add_space(25.0);
                    ui.separator();
                    ui.label(RichText::new("READ-ONLY DETECTION").size(11.0).color(GREEN));
                    ui.label(RichText::new("Silicon. Firmware. Operating system.\nEvery finding, with its evidence.").size(12.0).color(MUTED));
                    ui.label(RichText::new(format!("v{} · Linux / x86-64", env!("CARGO_PKG_VERSION"))).small().color(MUTED));
                    ui.label(RichText::new("Independent project. Not affiliated with AMD.").small().color(MUTED));
                });
            });
        egui::Panel::top("toolbar")
            .frame(
                egui::Frame::NONE
                    .fill(BACKGROUND)
                    .inner_margin(egui::Margin::symmetric(26, 16)),
            )
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("HARDWARE INTELLIGENCE")
                            .size(11.0)
                            .color(MUTED),
                    );
                    ui.separator();
                    if self.pending.is_some() {
                        ui.spinner();
                        ui.label("Scanning hardware…");
                    } else if let Some(time) = self.updated {
                        ui.label(
                            RichText::new(format!("Snapshot · {}s ago", time.elapsed().as_secs()))
                                .color(MUTED),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(self.pending.is_none(), egui::Button::new("Refresh"))
                            .clicked()
                        {
                            self.refresh(&ctx);
                        }
                        ui.checkbox(&mut self.auto_refresh, "Auto · 5s");
                        if ui
                            .add_enabled(self.report.is_some(), egui::Button::new("Copy JSON"))
                            .clicked()
                        {
                            if let Some(report) = &self.report {
                                ctx.copy_text(report.to_json());
                            }
                        }
                    });
                });
            });
        egui::CentralPanel::default().frame(egui::Frame::NONE.fill(BACKGROUND).inner_margin(26))
            .show(ui, |ui| {
                if let Some(error) = &self.error {
                    card(ui, |ui| {
                        ui.colored_label(ACCENT, "Refresh failed");
                        ui.label(error);
                        if self.report.is_some() { ui.label("Showing the previous snapshot."); }
                    });
                    ui.add_space(12.0);
                }
                let Some(report) = &self.report else {
                    ui.add_space(80.0);
                    ui.heading("Getting to know your machine");
                    ui.label("Collecting CPU, firmware and platform evidence.");
                    if self.pending.is_some() { ui.spinner(); }
                    return;
                };
                match self.view {
                    View::Overview => egui::ScrollArea::vertical().id_salt("overview").show(ui, |ui| overview(ui, report)).inner,
                    view => {
                        let title = match view { View::Category(category) => category.title(), _ => "All features" };
                        ui.label(RichText::new(title).size(28.0).strong());
                        ui.label(RichText::new("Measured state, backed by traceable evidence. Select a feature to inspect its probes.").color(MUTED));
                        ui.add_space(14.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search names, capabilities or evidence…").desired_width(330.0));
                            egui::ComboBox::from_id_salt("status-filter")
                                .selected_text(self.status.map_or("All states", Status::label))
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.status, None, "All states");
                                    for status in [Status::Enabled, Status::Present, Status::Disabled, Status::Absent, Status::Unknown] {
                                        ui.selectable_value(&mut self.status, Some(status), status.label());
                                    }
                                });
                            ui.checkbox(&mut self.attention_only, "Needs attention");
                            if ui.button("Clear").clicked() { self.search.clear(); self.status = None; self.attention_only = false; }
                        });
                        ui.add_space(10.0);
                        let selected = match view { View::Category(c) => Some(c), _ => None };
                        let query = self.search.to_lowercase();
                        let total = report.categories.iter().flat_map(|c| &c.features).filter(|f| matches_filter(f, selected, &query, self.status, self.attention_only)).count();
                        ui.label(RichText::new(format!("{total} features · absent and unknown states are included")).small().color(MUTED));
                        ui.add_space(8.0);
                        egui::ScrollArea::vertical().id_salt(format!("features-{view:?}")).show(ui, |ui| {
                            if total == 0 { ui.add_space(30.0); ui.heading("No matching features"); ui.label("Try another search or clear the filters."); }
                            for category in &report.categories {
                                let features: Vec<_> = category.features.iter().filter(|f| matches_filter(f, selected, &query, self.status, self.attention_only)).collect();
                                if features.is_empty() { continue; }
                                if selected.is_none() { section(ui, category.title, &format!("{} features", features.len())); }
                                for feature in features { feature_card(ui, feature); }
                            }
                        });
                    }
                }
            });
    }
}

impl eframe::App for Dashboard {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll(ctx);
    }
    fn ui(&mut self, ui: &mut Ui, _: &mut eframe::Frame) {
        self.draw(ui);
    }
}

fn nav(ui: &mut Ui, selected: &mut View, value: View, title: &str) {
    let active = *selected == value;
    let button = egui::Button::new(RichText::new(title).color(if active { ACCENT } else { MUTED }))
        .fill(if active {
            Color32::from_rgb(49, 36, 33)
        } else {
            Color32::TRANSPARENT
        })
        .stroke(Stroke::NONE)
        .corner_radius(8);
    if ui.add_sized([ui.available_width(), 33.0], button).clicked() {
        *selected = value;
    }
}

fn short_category(category: Category) -> &'static str {
    match category {
        Category::Isa => "Instruction sets",
        Category::Security => "Security",
        Category::Vulnerabilities => "Vulnerabilities",
        Category::ArchCaps => "Architecture",
        Category::Virtualization => "Virtualization",
        Category::Power => "Power & thermal",
        Category::Topology => "CPU topology",
        Category::Perf => "Performance monitoring",
        Category::Rdt => "Quality of service",
        Category::Accelerators => "Graphics & accelerators",
        Category::Platform => "Platform & connectivity",
        Category::Firmware => "Firmware",
    }
}

fn card<R>(ui: &mut Ui, contents: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(12)
        .inner_margin(18)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            contents(ui)
        })
        .inner
}

fn section(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.add_space(16.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).size(19.0).strong());
        ui.label(RichText::new(subtitle).size(12.0).color(MUTED));
    });
    ui.add_space(5.0);
}

fn status_color(status: Status) -> Color32 {
    match status {
        Status::Enabled => GREEN,
        Status::Present => CYAN,
        Status::Disabled => ACCENT,
        Status::Absent => MUTED,
        Status::Unknown => Color32::from_rgb(205, 182, 244),
    }
}

fn badge(ui: &mut Ui, status: Status) {
    let color = status_color(status);
    egui::Frame::NONE
        .fill(color.gamma_multiply(0.13))
        .corner_radius(5)
        .inner_margin(egui::Margin::symmetric(9, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(status.label().to_uppercase())
                    .size(10.0)
                    .strong()
                    .color(color),
            );
        });
}

fn find<'a>(report: &'a Report, id: &str) -> Option<&'a FeatureReport> {
    report
        .categories
        .iter()
        .flat_map(|c| &c.features)
        .find(|f| f.id == id)
}

fn evidence(feature: &FeatureReport) -> &str {
    feature
        .detections
        .iter()
        .max_by_key(|d| d.status.rank())
        .and_then(|d| d.detail.as_deref())
        .unwrap_or("No evidence exposed")
}

fn overview(ui: &mut Ui, report: &Report) {
    ui.label(RichText::new("Your machine, decoded.").size(30.0).strong());
    ui.label(
        RichText::new("A clear view of what your hardware supports and what Linux exposes.")
            .color(MUTED),
    );
    ui.add_space(18.0);
    card(ui, |ui| {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(84.0, 86.0), egui::Sense::hover());
            let chip = rect.shrink(15.0);
            ui.painter()
                .rect_filled(chip, 10, Color32::from_rgb(58, 39, 33));
            ui.painter()
                .rect_stroke(chip, 10, Stroke::new(1.5, ACCENT), egui::StrokeKind::Inside);
            for n in 0..5 {
                let x = chip.left() + 10.0 + n as f32 * 8.0;
                ui.painter().line_segment(
                    [egui::pos2(x, chip.top() - 6.0), egui::pos2(x, chip.top())],
                    Stroke::new(2.0, ACCENT),
                );
                ui.painter().line_segment(
                    [
                        egui::pos2(x, chip.bottom()),
                        egui::pos2(x, chip.bottom() + 6.0),
                    ],
                    Stroke::new(2.0, ACCENT),
                );
            }
            ui.painter().text(
                chip.center(),
                egui::Align2::CENTER_CENTER,
                "CPU",
                egui::FontId::proportional(16.0),
                ACCENT,
            );
            ui.vertical(|ui| {
                if let Some(cpu) = &report.identity {
                    ui.label(RichText::new(cpu.brand.trim()).size(23.0).strong());
                    if let Some(model) = &cpu.model_info {
                        ui.label(
                            RichText::new(format!("{}   /   {}", model.generation, model.codename))
                                .color(ACCENT),
                        );
                    }
                    ui.label(
                        RichText::new(format!(
                            "{} logical CPUs   ·   Microcode {}",
                            cpu.logical_cpus,
                            cpu.microcode.as_deref().unwrap_or("unknown")
                        ))
                        .color(MUTED),
                    );
                } else {
                    ui.heading("CPU identity unavailable");
                }
                if let Some(system) = &report.system {
                    ui.label(
                        RichText::new(format!(
                            "{}   ·   BIOS {}",
                            system.board, system.bios_version
                        ))
                        .color(MUTED),
                    );
                }
            });
        });
    });
    ui.add_space(12.0);
    let features: Vec<_> = report.categories.iter().flat_map(|c| &c.features).collect();
    let metrics = [
        ("FEATURES CHECKED", features.len(), Color32::WHITE),
        (
            "ENABLED / PRESENT",
            features
                .iter()
                .filter(|f| matches!(f.status, Status::Enabled | Status::Present))
                .count(),
            GREEN,
        ),
        (
            "NEEDS ATTENTION",
            features.iter().filter(|f| f.attention.is_some()).count(),
            ACCENT,
        ),
        (
            "UNKNOWN",
            features
                .iter()
                .filter(|f| f.status == Status::Unknown)
                .count(),
            Color32::from_rgb(205, 182, 244),
        ),
    ];
    ui.columns(4, |columns| {
        for (ui, (label, value, color)) in columns.iter_mut().zip(metrics) {
            card(ui, |ui| {
                ui.label(RichText::new(label).size(10.0).color(MUTED));
                ui.label(
                    RichText::new(value.to_string())
                        .size(32.0)
                        .strong()
                        .color(color),
                );
            });
        }
    });
    section(ui, "Thermal & cooling", "Kernel sensor snapshot");
    if ui.available_width() > 760.0 {
        ui.columns(2, |columns| {
            sensor_card(
                &mut columns[0],
                report,
                "temperatures",
                "Temperature sensors",
                "°C",
            );
            sensor_card(
                &mut columns[1],
                report,
                "fan_speeds",
                "Fan & pump speeds",
                "RPM",
            );
        });
    } else {
        sensor_card(ui, report, "temperatures", "Temperature sensors", "°C");
        ui.add_space(10.0);
        sensor_card(ui, report, "fan_speeds", "Fan & pump speeds", "RPM");
    }
    section(ui, "Power & connectivity", "Current configuration");
    for id in ["power_policy", "usb4"] {
        if let Some(feature) = find(report, id) {
            feature_card(ui, feature);
        }
    }
    section(ui, "System notes", "Evidence and availability");
    card(ui, |ui| {
        if report.notes.is_empty() {
            ui.label("No cross-probe discrepancies reported.");
        }
        for note in &report.notes {
            ui.label(RichText::new(note).color(MUTED));
        }
        ui.separator();
        ui.label(RichText::new(format!("Access level: {:?}. Unknown means the evidence is unavailable or inconclusive; it does not mean unsupported.", report.privilege)).color(MUTED));
        if let Some(system) = &report.system {
            ui.label(format!(
                "{} · {} · BIOS {} {} ({})",
                system.vendor,
                system.product,
                system.bios_vendor,
                system.bios_version,
                system.bios_date
            ));
        }
    });
}

fn sensor_card(ui: &mut Ui, report: &Report, id: &str, title: &str, unit: &str) {
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(title).size(17.0).strong());
            if let Some(feature) = find(report, id) {
                badge(ui, feature.status);
            }
        });
        ui.add_space(10.0);
        if let Some(feature) = find(report, id) {
            for line in evidence(feature).lines() {
                if let Some((name, value)) = sensor_reading(line, unit) {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            let label = name.split_once(' ').map_or(name, |(_, label)| label);
                            ui.label(RichText::new(label).size(13.0));
                            ui.label(
                                RichText::new(name.split(' ').next().unwrap_or(name))
                                    .size(10.0)
                                    .color(MUTED),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(if unit == "°C" {
                                    format!("{value:.1} {unit}")
                                } else {
                                    format!("{value:.0} {unit}")
                                })
                                .size(19.0)
                                .color(if unit == "°C" {
                                    CYAN
                                } else {
                                    GREEN
                                }),
                            );
                        });
                    });
                    ui.add_space(3.0);
                    ui.separator();
                } else {
                    ui.label(RichText::new(line).small().color(MUTED));
                }
            }
            ui.add_space(6.0);
            ui.label(
                RichText::new(if unit == "RPM" {
                    "Zero RPM can indicate a stopped fan or an unused header."
                } else {
                    "Kernel labels and raw readings; unused channels may report zero."
                })
                .small()
                .color(MUTED),
            );
        }
    });
}

fn sensor_reading<'a>(line: &'a str, unit: &str) -> Option<(&'a str, f64)> {
    let (name, value) = line.rsplit_once(": ")?;
    let value = value.strip_suffix(unit)?.trim().parse::<f64>().ok()?;
    value.is_finite().then_some((name, value))
}

fn feature_card(ui: &mut Ui, feature: &FeatureReport) {
    egui::Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(9)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                badge(ui, feature.status);
                ui.label(RichText::new(feature.name).size(16.0).strong());
                if feature.attention.is_some() {
                    ui.label(RichText::new("!  NEEDS ATTENTION").size(10.0).color(ACCENT));
                }
            });
            ui.label(RichText::new(feature.description).color(MUTED));
            if feature.inline_detail {
                for line in evidence(feature).lines() {
                    ui.label(
                        RichText::new(line)
                            .size(12.0)
                            .color(Color32::from_rgb(188, 202, 218)),
                    );
                }
            }
            egui::CollapsingHeader::new(format!(
                "Probe evidence · {} sources",
                feature.detections.len()
            ))
            .id_salt(feature.id)
            .show(ui, |ui| {
                if let Some(expectation) = feature.expectation {
                    ui.label(
                        RichText::new(format!(
                            "Class assessment: {:?} for {}. {}",
                            expectation.level, expectation.profile, expectation.rationale
                        ))
                        .color(ACCENT),
                    );
                }
                if feature.detections.is_empty() {
                    ui.label("No probe evidence is available.");
                }
                for detection in &feature.detections {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(detection.source);
                        badge(ui, detection.status);
                    });
                    ui.label(
                        detection
                            .detail
                            .as_deref()
                            .unwrap_or("No additional detail"),
                    );
                    ui.add_space(5.0);
                }
                ui.label(
                    RichText::new(format!("Feature ID: {}", feature.id))
                        .small()
                        .color(MUTED),
                );
            });
        });
    ui.add_space(5.0);
}

fn matches_filter(
    feature: &FeatureReport,
    category: Option<Category>,
    query: &str,
    status: Option<Status>,
    attention_only: bool,
) -> bool {
    if category.is_some_and(|c| c != feature.category)
        || status.is_some_and(|s| s != feature.status)
        || (attention_only && feature.attention.is_none())
    {
        return false;
    }
    query.is_empty()
        || [feature.id, feature.name, feature.description]
            .into_iter()
            .any(|text| text.to_lowercase().contains(query))
        || feature.detections.iter().any(|d| {
            d.source.to_lowercase().contains(query)
                || d.detail
                    .as_ref()
                    .is_some_and(|text| text.to_lowercase().contains(query))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use amd_features::model::{Detection, Privilege};
    use std::collections::HashMap;

    #[test]
    fn filtering_includes_unknown_and_absent_and_searches_evidence() {
        let report = Report::build(
            HashMap::from([(
                "usb4",
                vec![Detection::with_detail(
                    Status::Enabled,
                    "linux-sysfs",
                    "ASM4242",
                )],
            )]),
            None,
            None,
            Privilege::User,
        );
        let usb = find(&report, "usb4").unwrap();
        assert!(matches_filter(usb, None, "asm4242", None, false));
        assert!(!matches_filter(usb, Some(Category::Power), "", None, false));
        assert!(!matches_filter(usb, None, "", Some(Status::Unknown), false));
        assert!(!matches_filter(usb, None, "", None, true));
        assert_eq!(
            report
                .categories
                .iter()
                .flat_map(|c| &c.features)
                .filter(|f| matches_filter(f, None, "", None, false))
                .count(),
            amd_features::catalog::FEATURES.len()
        );
    }

    #[test]
    fn all_views_render_at_minimum_and_default_window_sizes() {
        let ctx = egui::Context::default();
        theme(&ctx);
        let mut app = Dashboard::new(Context::detect());
        app.report = Some(Report::build(HashMap::new(), None, None, Privilege::User));
        let views = [View::Overview, View::All]
            .into_iter()
            .chain(Category::ORDER.iter().copied().map(View::Category));
        for view in views {
            app.view = view;
            for size in [egui::vec2(880.0, 620.0), egui::vec2(1320.0, 900.0)] {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        ..Default::default()
                    },
                    |ui| app.draw(ui),
                );
                output.textures_delta.clear();
                assert!(!output.shapes.is_empty(), "empty view: {view:?}");
                assert!(output
                    .shapes
                    .iter()
                    .all(|shape| shape.clip_rect.is_finite()));
            }
        }
    }

    #[test]
    fn sidebar_mouse_navigation_switches_views() {
        let ctx = egui::Context::default();
        theme(&ctx);
        let mut app = Dashboard::new(Context::detect());
        app.report = Some(Report::build(HashMap::new(), None, None, Privilege::User));
        let frame = |app: &mut Dashboard, events: Vec<egui::Event>| {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1320.0, 900.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| app.draw(ui),
            );
            output.textures_delta.clear();
            output
        };
        frame(&mut app, Vec::new());
        let output = frame(&mut app, Vec::new());
        let pos = output
            .shapes
            .iter()
            .find_map(|shape| {
                if let egui::Shape::Text(text) = &shape.shape {
                    (text.galley.text() == "All features")
                        .then(|| text.pos + text.galley.size() / 2.0)
                } else {
                    None
                }
            })
            .expect("All features navigation is rendered");
        for pressed in [true, false] {
            frame(
                &mut app,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        assert_eq!(app.view, View::All);
    }

    #[test]
    fn sensor_parser_handles_colons_negative_and_zero_values() {
        assert_eq!(
            sensor_reading("r8169_0_a00:00/hwmon0 temp1: -1.250 °C", "°C"),
            Some(("r8169_0_a00:00/hwmon0 temp1", -1.25))
        );
        assert_eq!(sensor_reading("Fan: 0 RPM", "RPM"), Some(("Fan", 0.0)));
        assert_eq!(sensor_reading("Fan: disabled", "RPM"), None);
        assert_eq!(sensor_reading("Temp: NaN °C", "°C"), None);
    }
}
