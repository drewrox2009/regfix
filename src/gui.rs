use eframe::egui;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::fs::File;
use memmap::MmapOptions;
use crate::types::*;
use crate::registry;

const SPACING: f32 = 10.0;
const INNER_SPACING: f32 = 5.0;
const LOGO_SIZE: f32 = 48.0;
const CLOSE_BUTTON_SIZE: f32 = 32.0;
const HEADER_HEIGHT: f32 = 48.0;
const HEADER_WITH_FILE_HEIGHT: f32 = 100.0;

const CONTENT_PADDING: f32 = 20.0;  // Added padding constant
const WINDOW_ROUNDING: f32 = 15.0;  // Added window rounding constant

// Embed the logo directly into the binary
const LOGO_BYTES: &[u8] = include_bytes!("../assets/logo.png");

#[derive(Default)]
struct UiState {
    show_fix_dialog: bool,
    fix_selections: Vec<bool>,
    status_message: String,
    selected_file: Option<std::path::PathBuf>,
    analysis_result: Option<Arc<AnalysisResult>>,
    selected_fixes: Vec<FixType>,
}

pub struct RegistryFixerApp {
    tx: Sender<Message>,
    rx: Receiver<Message>,
    ui_state: Arc<Mutex<UiState>>,
    logo: Option<egui::TextureHandle>,
}

// New message type for UI updates
enum UiUpdate {
    ToggleFixSelection(usize),
    ShowFixDialog(Vec<FixType>),
    ClearFixDialog,
}

impl RegistryFixerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Set up dark theme
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        style.spacing.item_spacing = egui::vec2(SPACING, SPACING);
        style.spacing.window_margin = egui::Margin::same(SPACING);
        style.spacing.button_padding = egui::vec2(SPACING, SPACING/2.0);
        
        style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(32, 33, 36);
        style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(41, 42, 45);
        style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(53, 54, 58);
        style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(66, 69, 73);
        style.visuals.window_fill = egui::Color32::from_rgb(32, 33, 36);
        style.visuals.panel_fill = egui::Color32::from_rgb(32, 33, 36);
        
        style.visuals.selection.bg_fill = egui::Color32::from_rgb(76, 119, 255);
        
        cc.egui_ctx.set_style(style);
        
        // Load the logo from embedded bytes
        let logo = {
            let image = image::load_from_memory(LOGO_BYTES)
                .unwrap_or_else(|_| {
                    // Create a 1x1 pixel fallback image if loading fails
                    image::DynamicImage::new_rgb8(1, 1)
                });
            let size = [image.width() as _, image.height() as _];
            let image_buffer = image.to_rgba8();
            let pixels = image_buffer.as_flat_samples();
            let color_image = egui::ColorImage::from_rgba_unmultiplied(
                size,
                pixels.as_slice(),
            );
            Some(cc.egui_ctx.load_texture(
                "logo",
                color_image,
                egui::TextureOptions::default(),
            ))
        };
        
        let (tx, rx) = channel();
        
        Self {
            tx,
            rx,
            ui_state: Arc::new(Mutex::new(UiState::default())),
            logo,
        }
    }

    fn update_ui_state(&self, update: UiUpdate) {
        let mut state = self.ui_state.lock().unwrap();
        match update {
            UiUpdate::ToggleFixSelection(index) => {
                if let Some(selection) = state.fix_selections.get_mut(index) {
                    *selection = !*selection;
                }
            }
            UiUpdate::ShowFixDialog(fixes) => {
                state.show_fix_dialog = true;
                state.selected_fixes = fixes;
            }
            UiUpdate::ClearFixDialog => {
                state.show_fix_dialog = false;
                state.selected_fixes.clear();
            }
        }
    }

    fn process_messages(&self) {
        while let Ok(message) = self.rx.try_recv() {
            match message {
                Message::FileSelected(path) => {
                    let mut state = self.ui_state.lock().unwrap();
                    state.selected_file = Some(path.clone());
                    state.status_message = "File selected. Analyzing...".to_string();
                    drop(state);
                    
                    let tx = self.tx.clone();
                    let path_str = path.to_string_lossy().to_string();
                    std::thread::spawn(move || {
                        match registry::check_registry_file(&path_str) {
                            Ok(result) => {
                                tx.send(Message::AnalysisComplete(result)).unwrap();
                            }
                            Err(e) => {
                                tx.send(Message::FixComplete(format!("Analysis failed: {}", e))).unwrap();
                            }
                        }
                    });
                }
                Message::AnalysisComplete(result) => {
                    let len = result.issues.len();
                    let result = Arc::new(result);
                    let mut state = self.ui_state.lock().unwrap();
                    state.analysis_result = Some(result);
                    state.status_message = "Analysis complete.".to_string();
                    state.fix_selections = vec![false; len];
                }
                Message::FixSelected(fixes) => {
                    let analysis = {
                        let state = self.ui_state.lock().unwrap();
                        state.analysis_result.clone()
                    };
                    
                    if let Some(analysis) = analysis {
                        let file_path = analysis.file_info.path.clone();
                        let tx = self.tx.clone();
                        
                        std::thread::spawn(move || {
                            match registry::backup_file(&file_path) {
                                Ok(_backup_path) => {
                                    let mut needs_checksum_update = false;
                                    let mut error_occurred = false;
                                    
                                    for fix_type in fixes {
                                        if let Some(issue) = analysis.issues.iter()
                                            .find(|i| i.fix_type.as_ref() == Some(&fix_type))
                                        {
                                            match (&fix_type, &issue.fix_data) {
                                                (FixType::HiveBinsSize, Some(FixData::HiveBinsSize(new_size))) => {
                                                    if let Err(e) = registry::update_hive_bins_size(&file_path, *new_size) {
                                                        tx.send(Message::FixComplete(format!("Failed to update hive bins size: {}", e))).unwrap();
                                                        error_occurred = true;
                                                        break;
                                                    }
                                                    needs_checksum_update = true;
                                                }
                                                (FixType::Checksum, Some(FixData::Checksum(new_checksum))) => {
                                                    if let Err(e) = registry::update_checksum(&file_path, *new_checksum) {
                                                        tx.send(Message::FixComplete(format!("Failed to update checksum: {}", e))).unwrap();
                                                        error_occurred = true;
                                                        break;
                                                    }
                                                }
                                                (FixType::SequenceNumbers, Some(FixData::SequenceNumbers(primary, secondary))) => {
                                                    if let Err(e) = registry::update_sequence_numbers(&file_path, *primary, *secondary) {
                                                        tx.send(Message::FixComplete(format!("Failed to update sequence numbers: {}", e))).unwrap();
                                                        error_occurred = true;
                                                        break;
                                                    }
                                                    needs_checksum_update = true;
                                                }
                                                _ => {}
                                            }
                                        }
                                    }

                                    if !error_occurred {
                                        if needs_checksum_update {
                                            match File::open(&file_path) {
                                                Ok(file) => {
                                                    if let Ok(mmap) = unsafe { MmapOptions::new().map(&file) } {
                                                        let new_checksum = registry::calculate_header_checksum(&mmap);
                                                        if let Err(e) = registry::update_checksum(&file_path, new_checksum) {
                                                            tx.send(Message::FixComplete(format!("Failed to update final checksum: {}", e))).unwrap();
                                                            return;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    tx.send(Message::FixComplete(format!("Failed to open file for checksum update: {}", e))).unwrap();
                                                    return;
                                                }
                                            }
                                        }
                                        tx.send(Message::FixComplete("All fixes applied successfully.".to_string())).unwrap();
                                    }
                                }
                                Err(e) => {
                                    tx.send(Message::FixComplete(format!("Failed to create backup: {}", e))).unwrap();
                                }
                            }
                        });
                    }
                }
                Message::FixComplete(msg) => {
                    let selected_file = {
                        let mut state = self.ui_state.lock().unwrap();
                        state.status_message = msg;
                        state.show_fix_dialog = false;
                        state.selected_file.clone()
                    };
                    
                    if let Some(path) = selected_file {
                        let tx = self.tx.clone();
                        let path_str = path.to_string_lossy().to_string();
                        std::thread::spawn(move || {
                            if let Ok(result) = registry::check_registry_file(&path_str) {
                                tx.send(Message::AnalysisComplete(result)).unwrap();
                            }
                        });
                    }
                }
            }
        }
    }

    fn render_file_info(ui: &mut egui::Ui, file_info: &FileInfo) {
        ui.add_space(SPACING);
        egui::Grid::new("file_info_grid")
            .striped(true)
            .spacing(egui::vec2(SPACING * 2.0, INNER_SPACING))
            .show(ui, |ui| {
                let label_color = ui.style().visuals.widgets.noninteractive.text_color();
                
                ui.label(egui::RichText::new("Path:").color(label_color));
                ui.label(&file_info.path);
                ui.end_row();

                ui.label(egui::RichText::new("Size:").color(label_color));
                ui.label(format!("{} bytes (0x{:X})", file_info.size, file_info.size));
                ui.end_row();

                ui.label(egui::RichText::new("Signature:").color(label_color));
                ui.label(&file_info.signature);
                ui.end_row();

                ui.label(egui::RichText::new("Sequence Numbers:").color(label_color));
                ui.label(format!("Primary: {}, Secondary: {}", 
                    file_info.primary_seq_num, file_info.secondary_seq_num));
                ui.end_row();

                ui.label(egui::RichText::new("Last Written:").color(label_color));
                ui.label(format!("0x{:016X}", file_info.last_written));
                ui.end_row();

                ui.label(egui::RichText::new("Version:").color(label_color));
                ui.label(format!("{}.{}", file_info.major_version, file_info.minor_version));
                ui.end_row();

                ui.label(egui::RichText::new("Hive Bins Size:").color(label_color));
                ui.label(format!("Stored: {} bytes, Measured: {} bytes", 
                    file_info.hive_bins_size, file_info.measured_hive_bins_size));
                ui.end_row();

                ui.label(egui::RichText::new("Checksum:").color(label_color));
                ui.label(format!("Stored: 0x{:08X}, Calculated: 0x{:08X}",
                    file_info.stored_checksum, file_info.calculated_checksum));
                ui.end_row();
            });
        ui.add_space(SPACING);
    }

    fn render_header(&self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let (has_file, file_path) = {
            let state = self.ui_state.lock().unwrap();
            (state.selected_file.is_some(), state.selected_file.clone())
        };

        if has_file {
            // Regular header layout when a file is selected
            let available_rect = ui.available_rect_before_wrap();
            let header_rect = egui::Rect::from_min_size(
                available_rect.min,
                egui::vec2(available_rect.width(), HEADER_WITH_FILE_HEIGHT),
            );

            // Make the entire header area draggable
            let header_response = ui.interact(header_rect, ui.id().with("drag_area"), egui::Sense::click());
            if header_response.is_pointer_button_down_on() {
                frame.drag_window();
            }

            // Header content
            ui.allocate_ui_at_rect(header_rect, |ui| {
                ui.vertical(|ui| {
                    ui.add_space(SPACING);  // Add spacing at the top

                    // First show the file path and close button
                    ui.horizontal(|ui| {
                        if let Some(path) = &file_path {
                            ui.label(egui::RichText::new(format!("Selected file: {}", path.display()))
                                .size(14.0));
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                            let close_button = ui.add_sized(
                                egui::vec2(CLOSE_BUTTON_SIZE, CLOSE_BUTTON_SIZE),
                                egui::Button::new(
                                    egui::RichText::new("✕")
                                        .size(20.0)
                                        .color(egui::Color32::WHITE)
                                ).fill(if ui.ui_contains_pointer() {
                                    egui::Color32::from_rgb(255, 88, 88)
                                } else {
                                    egui::Color32::from_rgb(66, 69, 73)
                                })
                            );
                            
                            if close_button.clicked() {
                                frame.close();
                            }
                        });
                    });

                    ui.add_space(SPACING * 1.5);  // Increased spacing between sections

                    // Then show the logo, title and select button
                    ui.horizontal(|ui| {
                        if let Some(logo) = &self.logo {
                            ui.image(logo, egui::vec2(LOGO_SIZE, LOGO_SIZE));
                            ui.add_space(SPACING);
                        }
                        
                        ui.heading(egui::RichText::new("MDC RegFix")
                            .size(24.0)
                            .strong());
                        
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // File selection button
                            if ui.button(egui::RichText::new("Select Registry File")
                                .size(16.0))
                                .clicked() 
                            {
                                if let Some(path) = rfd::FileDialog::new()
                                    .set_title("Select Registry File")
                                    .pick_file() 
                                {
                                    self.tx.send(Message::FileSelected(path)).unwrap();
                                }
                            }
                        });
                    });
                    ui.add_space(SPACING);  // Add spacing at the bottom
                });
            });
        } else {
            // Centered layout when no file is selected
            ui.horizontal(|ui| {
                let available_rect = ui.available_rect_before_wrap();
                let header_rect = egui::Rect::from_min_size(
                    available_rect.min,
                    egui::vec2(available_rect.width(), HEADER_HEIGHT),
                );

                // Make the header draggable
                let header_response = ui.interact(header_rect, ui.id().with("drag_area"), egui::Sense::click());
                if header_response.is_pointer_button_down_on() {
                    frame.drag_window();
                }

                // Close button in top-right
                ui.allocate_ui_at_rect(header_rect, |ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        let close_button = ui.add_sized(
                            egui::vec2(CLOSE_BUTTON_SIZE, CLOSE_BUTTON_SIZE),
                            egui::Button::new(
                                egui::RichText::new("✕")
                                    .size(20.0)
                                    .color(egui::Color32::WHITE)
                            ).fill(if ui.ui_contains_pointer() {
                                egui::Color32::from_rgb(255, 88, 88)
                            } else {
                                egui::Color32::from_rgb(66, 69, 73)
                            })
                        );
                        
                        if close_button.clicked() {
                            frame.close();
                        }
                    });
                });
            });

            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 3.0);
                
                if let Some(logo) = &self.logo {
                    ui.image(logo, egui::vec2(LOGO_SIZE * 2.0, LOGO_SIZE * 2.0));
                    ui.add_space(SPACING);
                }
                
                ui.heading(egui::RichText::new("MDC RegFix")
                    .size(24.0)
                    .strong());
                
                ui.add_space(SPACING * 2.0);
                
                if ui.button(egui::RichText::new("Select Registry File")
                    .size(20.0))
                    .clicked() 
                {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select Registry File")
                        .pick_file() 
                    {
                        self.tx.send(Message::FileSelected(path)).unwrap();
                    }
                }
            });
        }
    }

    fn render_issues(&self, ui: &mut egui::Ui) {
        // Get the analysis result and fix selections upfront
        let (analysis_result, fix_selections) = {
            let state = self.ui_state.lock().unwrap();
            (state.analysis_result.clone(), state.fix_selections.clone())
        };

        if let Some(result) = analysis_result {
            ui.add_space(SPACING);
            ui.heading(egui::RichText::new("Issues").size(20.0));
            ui.add_space(INNER_SPACING);

            let fixable_issues: Vec<_> = result.issues.iter()
                .filter(|i| i.fix_type.is_some())
                .collect();
            
            if !fixable_issues.is_empty() {
                if ui.button(egui::RichText::new("Fix All Issues")
                    .size(16.0))
                    .clicked() 
                {
                    let fixes: Vec<FixType> = fixable_issues.iter()
                        .filter_map(|i| i.fix_type.clone())
                        .collect();
                    
                    self.update_ui_state(UiUpdate::ShowFixDialog(fixes.clone()));
                    self.tx.send(Message::FixSelected(fixes)).unwrap();
                    return;
                }
            }

            ui.add_space(INNER_SPACING);

            for (i, issue) in result.issues.iter().enumerate() {
                if issue.fix_type.is_some() {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            match issue.severity {
                                IssueSeverity::Critical => {
                                    ui.label(egui::RichText::new("CRITICAL")
                                        .color(egui::Color32::from_rgb(255, 88, 88))
                                        .size(16.0));
                                }
                                IssueSeverity::Warning => {
                                    ui.label(egui::RichText::new("WARNING")
                                        .color(egui::Color32::from_rgb(255, 180, 76))
                                        .size(16.0));
                                }
                            }
                            ui.label(egui::RichText::new(&issue.message).size(16.0));
                        });

                        ui.add_space(INNER_SPACING);
                        if let Some(details) = &issue.details {
                            ui.label(egui::RichText::new(details)
                                .color(ui.style().visuals.widgets.noninteractive.text_color()));
                        }

                        ui.add_space(INNER_SPACING);
                        let mut is_selected = fix_selections.get(i).cloned().unwrap_or(false);
                        if ui.checkbox(&mut is_selected, "Select for fixing").clicked() {
                            self.update_ui_state(UiUpdate::ToggleFixSelection(i));
                        }
                    });
                    ui.add_space(INNER_SPACING);
                }
            }
        }
    }

    fn render_fix_dialog(&self, ctx: &egui::Context) {
        let (show_dialog, selected_fixes) = {
            let state = self.ui_state.lock().unwrap();
            (state.show_fix_dialog, state.selected_fixes.clone())
        };

        if show_dialog {
            egui::Window::new("Confirm Fixes")
                .fixed_size(egui::vec2(400.0, 200.0))
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.heading(egui::RichText::new("Selected Fixes").size(18.0));
                    ui.add_space(SPACING);
                    
                    for fix in &selected_fixes {
                        ui.label(egui::RichText::new(format!("• {:?}", fix)).size(14.0));
                    }
                    
                    ui.add_space(SPACING);
                    ui.separator();
                    ui.add_space(SPACING);
                    
                    ui.label(egui::RichText::new("WARNING")
                        .color(egui::Color32::from_rgb(255, 180, 76))
                        .size(16.0));
                    ui.label("A backup will be created before making any changes.");
                    ui.label("Making changes to the header will require recalculating the checksum.");
                    
                    ui.add_space(SPACING);
                    
                    ui.horizontal(|ui| {
                        if ui.button(egui::RichText::new("Apply Fixes")
                            .size(16.0))
                            .clicked() 
                        {
                            self.tx.send(Message::FixSelected(selected_fixes.clone())).unwrap();
                        }
                        if ui.button(egui::RichText::new("Cancel")
                            .size(16.0))
                            .clicked() 
                        {
                            self.update_ui_state(UiUpdate::ClearFixDialog);
                        }
                    });
                });
        }
    }
}


impl eframe::App for RegistryFixerApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.process_messages();

        // Set up the frame
        let frame_stroke = egui::Stroke::none();
        let rounding = egui::Rounding::same(WINDOW_ROUNDING);
        
        egui::CentralPanel::default()
            .frame(egui::Frame::none()
                .fill(ctx.style().visuals.window_fill())
                .stroke(frame_stroke)
                .rounding(rounding)
                .inner_margin(CONTENT_PADDING))  // Add padding around all content
            .show(ctx, |ui| {
                // Create a container with rounded corners
                egui::Frame::none()
                    .fill(ctx.style().visuals.window_fill())
                    .rounding(rounding)
                    .show(ui, |ui| {
                        self.render_header(ui, frame);
                        ui.add_space(SPACING);

                        let has_analysis = {
                            let state = self.ui_state.lock().unwrap();
                            state.analysis_result.is_some()
                        };

                        if has_analysis {
                            egui::ScrollArea::vertical()
                                .auto_shrink([false; 2])
                                .show(ui, |ui| {
                                    if let Ok(state) = self.ui_state.lock() {
                                        if let Some(result) = &state.analysis_result {
                                            ui.heading(egui::RichText::new("File Information").size(20.0));
                                            Self::render_file_info(ui, &result.file_info);
                                            ui.separator();
                                        }
                                    }
                                    self.render_issues(ui);
                                });
                        }

                        if let Ok(state) = self.ui_state.lock() {
                            if !state.status_message.is_empty() {
                                ui.separator();
                                ui.label(egui::RichText::new(&state.status_message)
                                    .size(14.0)
                                    .color(egui::Color32::from_rgb(76, 175, 80)));
                            }
                        }
                    });
            });

        self.render_fix_dialog(ctx);
    }
}

