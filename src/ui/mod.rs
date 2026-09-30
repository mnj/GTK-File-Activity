// SPDX-License-Identifier: MIT

mod detail;
mod graph;
mod row;
mod table;

use crate::collect::{self, Control};
use crate::model::{format_rate, ProcSnapshot, Snapshot};
use detail::Detail;
use graph::Graph;
use gtk::gio::{self, ListStore};
use gtk::glib;
use gtk::prelude::*;
use gtk::{
    Align, CustomFilter, FilterChange, FilterListModel, Label, Orientation, ScrolledWindow,
    SearchBar, SearchEntry, SingleSelection, SortListModel, Stack, ToggleButton,
};
use libadwaita as adw;
use libadwaita::prelude::*;
use row::FileRow;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::Duration;

const APP_ID: &str = "local.gtk.FileActivity";
const STYLE: &str = include_str!("style.css");

type Procs = Rc<RefCell<HashMap<(u64, u64), Vec<ProcSnapshot>>>>;

pub fn run() {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_startup(|_| load_style());
    app.connect_activate(build_window);
    let code = app.run();
    std::process::exit(code.value());
}

fn load_style() {
    let Some(display) = gtk::gdk::Display::default() else {
        return;
    };
    let css = gtk::CssProvider::new();
    css.load_from_string(STYLE);
    gtk::style_context_add_provider_for_display(
        &display,
        &css,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

fn build_window(app: &adw::Application) {
    let privileged = collect::is_root();
    let ctrl = Control::new(Duration::from_secs(1), !privileged);
    // Whether the probes are running, which decides what the empty page says.
    let rates_on = Rc::new(Cell::new(privileged));

    // Data pipeline: store -> filter -> sort -> selection.
    let query = Rc::new(RefCell::new(String::new()));
    let filter = {
        let query = query.clone();
        CustomFilter::new(move |obj| {
            let q = query.borrow();
            q.is_empty()
                || obj
                    .downcast_ref::<FileRow>()
                    .is_some_and(|row| row.haystack().contains(q.as_str()))
        })
    };
    let store = ListStore::new::<FileRow>();
    let filtered = FilterListModel::new(Some(store.clone()), Some(filter.clone()));
    let sorted = SortListModel::new(Some(filtered), None::<gtk::Sorter>);
    let selection = SingleSelection::builder()
        .model(&sorted)
        .autoselect(false)
        .can_unselect(true)
        .build();
    let view = table::build(&selection);
    sorted.set_sorter(view.sorter().as_ref());

    // Summary card with live totals and the history graph.
    let (read_box, read_value) = stat_block("Read", "read");
    let (write_box, write_value) = stat_block("Write", "write");
    let files_value = Label::builder()
        .halign(Align::End)
        .valign(Align::Center)
        .hexpand(true)
        .build();
    files_value.add_css_class("dim-label");
    let stats = gtk::Box::new(Orientation::Horizontal, 28);
    stats.set_margin_top(12);
    stats.set_margin_bottom(6);
    stats.set_margin_start(14);
    stats.set_margin_end(14);
    stats.append(&read_box);
    stats.append(&write_box);
    stats.append(&files_value);
    let graph = Graph::new();
    let card = gtk::Box::new(Orientation::Vertical, 0);
    card.add_css_class("card");
    card.set_overflow(gtk::Overflow::Hidden);
    card.set_margin_start(12);
    card.set_margin_end(12);
    card.set_margin_top(12);
    card.set_margin_bottom(6);
    card.set_tooltip_text(Some(
        "Logical bytes moved by read and write calls, including page cache hits. \
         Memory-mapped access is not counted.",
    ));
    card.append(&stats);
    card.append(&graph.widget);

    // File list, or an empty state when nothing matches.
    let scroll = ScrolledWindow::builder()
        .child(&view)
        .hexpand(true)
        .vexpand(true)
        .build();
    let empty = adw::StatusPage::builder()
        .icon_name("folder-saved-search-symbolic")
        .vexpand(true)
        .build();
    empty.add_css_class("compact");
    let pages = Stack::new();
    pages.add_named(&scroll, Some("table"));
    pages.add_named(&empty, Some("empty"));
    let refresh_pages = {
        let (pages, sorted, query, empty, rates_on) = (
            pages.clone(),
            sorted.clone(),
            query.clone(),
            empty.clone(),
            rates_on.clone(),
        );
        Rc::new(move || {
            if sorted.n_items() > 0 {
                pages.set_visible_child_name("table");
                return;
            }
            if query.borrow().is_empty() {
                empty.set_title("No File Activity");
                empty.set_description(Some(if rates_on.get() {
                    "Files appear here while programs read or write them."
                } else {
                    "Turn on Show Idle Files in the menu to list files that are open."
                }));
            } else {
                empty.set_title("No Matching Files");
                empty.set_description(Some("Try a different search."));
            }
            pages.set_visible_child_name("empty");
        })
    };
    {
        let refresh = refresh_pages.clone();
        sorted.connect_items_changed(move |_, _, _, _| refresh());
    }
    refresh_pages();

    let detail = Detail::new();
    let split = adw::OverlaySplitView::builder()
        .sidebar_position(gtk::PackType::End)
        .min_sidebar_width(300.0)
        .max_sidebar_width(460.0)
        .sidebar_width_fraction(0.34)
        .content(&pages)
        .sidebar(&detail.widget)
        .show_sidebar(true)
        .build();

    let banner = adw::Banner::builder().build();
    {
        let ctrl = ctrl.clone();
        banner.connect_button_clicked(move |_| ctrl.request_helper());
    }

    let search_entry = SearchEntry::builder()
        .placeholder_text("Filter by file or process")
        .hexpand(true)
        .max_width_chars(48)
        .build();
    let search_bar = SearchBar::builder().child(&search_entry).build();
    search_bar.connect_entry(&search_entry);

    let content = gtk::Box::new(Orientation::Vertical, 0);
    content.append(&banner);
    content.append(&search_bar);
    content.append(&card);
    content.append(&split);
    split.set_vexpand(true);

    // Header.
    let title = adw::WindowTitle::new("File Activity", "Waiting for the first sample…");
    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&title));
    let search_button = ToggleButton::builder()
        .icon_name("system-search-symbolic")
        .tooltip_text("Search (Ctrl+F)")
        .build();
    search_button
        .bind_property("active", &search_bar, "search-mode-enabled")
        .bidirectional()
        .sync_create()
        .build();
    let pause_button = ToggleButton::builder()
        .icon_name("media-playback-pause-symbolic")
        .tooltip_text("Pause (Ctrl+P)")
        .action_name("win.pause")
        .build();
    let sidebar_button = ToggleButton::builder()
        .icon_name("sidebar-show-right-symbolic")
        .tooltip_text("Details")
        .build();
    sidebar_button
        .bind_property("active", &split, "show-sidebar")
        .bidirectional()
        .sync_create()
        .build();
    let menu_button = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&primary_menu())
        .primary(true)
        .tooltip_text("Main Menu")
        .build();
    header.pack_start(&search_button);
    header.pack_end(&menu_button);
    header.pack_end(&sidebar_button);
    header.pack_end(&pause_button);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&content));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("File Activity")
        .default_width(1180)
        .default_height(760)
        .content(&toolbar)
        .build();
    window.set_size_request(360, 400);
    search_bar.set_key_capture_widget(Some(&window));
    add_narrow_breakpoint(&window, &split);

    install_actions(app, &window, &ctrl, &search_bar, &pause_button, privileged);

    {
        let (query, filter, refresh) = (query.clone(), filter.clone(), refresh_pages.clone());
        search_entry.connect_search_changed(move |entry| {
            *query.borrow_mut() = entry.text().to_lowercase();
            filter.changed(FilterChange::Different);
            refresh();
        });
    }

    let procs: Procs = Rc::default();
    {
        let (detail, procs) = (detail.clone(), procs.clone());
        selection.connect_selection_changed(move |selection, _, _| {
            show_detail(&detail, selection, &procs);
        });
    }
    detail.update(None);

    let (tx, rx) = async_channel::bounded(1);
    collect::spawn(tx, ctrl.clone());
    {
        let ctrl = ctrl.clone();
        window.connect_close_request(move |_| {
            ctrl.stop();
            glib::Propagation::Proceed
        });
    }

    let window_tick = window.clone();
    glib::spawn_future_local(async move {
        while let Ok(snap) = rx.recv().await {
            apply_snapshot(&store, &snap);
            *procs.borrow_mut() = snap
                .files
                .iter()
                .map(|file| ((file.dev, file.ino), file.processes.clone()))
                .collect();
            show_detail(&detail, &selection, &procs);
            read_value.set_label(&format_rate(snap.total_read_bps));
            write_value.set_label(&format_rate(snap.total_write_bps));
            files_value.set_label(&format!("{} files", snap.files.len()));
            title.set_subtitle(&format!(
                "{} · probes {}/{}",
                plural(snap.files.len(), "file"),
                snap.attached,
                snap.expected
            ));
            // Listing every open file is the fallback without rates. Once the
            // probes are live the list should be the files doing I/O.
            if snap.attached > 0 && !rates_on.get() {
                if let Some(idle) = window_tick.lookup_action("idle") {
                    idle.change_state(&false.to_variant());
                }
            }
            rates_on.set(snap.attached > 0);
            let problem = snap.failed.join("; ");
            if snap.needs_auth {
                banner.set_title(if problem.is_empty() {
                    "Read and write rates need administrator access. Open files are listed meanwhile."
                } else {
                    &problem
                });
                banner.set_button_label(Some("Enable Rates"));
                banner.set_revealed(true);
            } else if problem.is_empty() {
                banner.set_revealed(false);
            } else {
                banner.set_title(&format!("Some probes did not attach: {problem}"));
                banner.set_button_label(None);
                banner.set_revealed(true);
            }
            graph.update(snap.graph);
            filter.changed(FilterChange::Different);
        }
    });

    window.present();
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// A coloured dot, a caption and the big number.
fn stat_block(caption: &str, class: &str) -> (gtk::Box, Label) {
    let dot = gtk::Box::builder().valign(Align::Center).build();
    dot.add_css_class("stat-dot");
    dot.add_css_class(class);
    let name = Label::new(Some(caption));
    name.add_css_class("dim-label");
    let head = gtk::Box::new(Orientation::Horizontal, 6);
    head.append(&dot);
    head.append(&name);
    let value = Label::builder().xalign(0.0).label("0 B/s").build();
    value.add_css_class("stat-value");
    value.add_css_class("numeric");
    let block = gtk::Box::new(Orientation::Vertical, 0);
    block.append(&head);
    block.append(&value);
    (block, value)
}

fn primary_menu() -> gio::Menu {
    let menu = gio::Menu::new();
    let view = gio::Menu::new();
    view.append(Some("Show Idle Files"), Some("win.idle"));
    menu.append_section(None, &view);
    let rate = gio::Menu::new();
    for (label, ms) in [("0.5 seconds", "500"), ("1 second", "1000"), ("2 seconds", "2000"), ("5 seconds", "5000")] {
        let item = gio::MenuItem::new(Some(label), None);
        item.set_action_and_target_value(Some("win.interval"), Some(&ms.to_variant()));
        rate.append_item(&item);
    }
    menu.append_submenu(Some("Refresh Interval"), &rate);
    let app = gio::Menu::new();
    app.append(Some("About File Activity"), Some("win.about"));
    menu.append_section(None, &app);
    menu
}

fn install_actions(
    app: &adw::Application,
    window: &adw::ApplicationWindow,
    ctrl: &std::sync::Arc<Control>,
    search_bar: &SearchBar,
    pause_button: &ToggleButton,
    privileged: bool,
) {
    let pause = gio::SimpleAction::new_stateful("pause", None, &false.to_variant());
    {
        let (ctrl, button) = (ctrl.clone(), pause_button.clone());
        pause.connect_change_state(move |action, value| {
            let paused = value.and_then(|v| v.get::<bool>()).unwrap_or(false);
            action.set_state(&paused.to_variant());
            ctrl.set_paused(paused);
            button.set_icon_name(if paused {
                "media-playback-start-symbolic"
            } else {
                "media-playback-pause-symbolic"
            });
        });
    }
    window.add_action(&pause);

    let idle = gio::SimpleAction::new_stateful("idle", None, &(!privileged).to_variant());
    {
        let ctrl = ctrl.clone();
        idle.connect_change_state(move |action, value| {
            let show = value.and_then(|v| v.get::<bool>()).unwrap_or(false);
            action.set_state(&show.to_variant());
            ctrl.set_show_idle(show);
        });
    }
    window.add_action(&idle);

    let interval = gio::SimpleAction::new_stateful(
        "interval",
        Some(glib::VariantTy::STRING),
        &"1000".to_variant(),
    );
    {
        let ctrl = ctrl.clone();
        interval.connect_activate(move |action, value| {
            let Some(value) = value else { return };
            let ms = value.str().and_then(|s| s.parse().ok()).unwrap_or(1000);
            action.set_state(value);
            ctrl.set_interval(Duration::from_millis(ms));
        });
    }
    window.add_action(&interval);

    let find = gio::SimpleAction::new("find", None);
    {
        let search_bar = search_bar.clone();
        find.connect_activate(move |_, _| search_bar.set_search_mode(true));
    }
    window.add_action(&find);

    let about = gio::SimpleAction::new("about", None);
    {
        let window = window.clone();
        about.connect_activate(move |_, _| show_about(&window));
    }
    window.add_action(&about);

    app.set_accels_for_action("win.pause", &["<Control>p"]);
    app.set_accels_for_action("win.find", &["<Control>f"]);
    app.set_accels_for_action("win.about", &["F1"]);
}

fn show_about(window: &adw::ApplicationWindow) {
    let about = adw::AboutDialog::builder()
        .application_name("File Activity")
        .application_icon("drive-harddisk")
        .developer_name("Michael Jensen")
        .version(env!("CARGO_PKG_VERSION"))
        .comments("Per-file read and write rates for Linux, in the style of Windows Resource Monitor.")
        .copyright("© 2026 Michael Jensen")
        .license_type(gtk::License::MitX11)
        .build();
    about.add_legal_section(
        "eBPF program",
        Some("© Michael Jensen"),
        gtk::License::Gpl20Only,
        None,
    );
    about.present(Some(window));
}

/// Below about 760 px the details sidebar overlays the list instead of sharing the row.
fn add_narrow_breakpoint(window: &adw::ApplicationWindow, split: &adw::OverlaySplitView) {
    let condition = adw::BreakpointCondition::new_length(
        adw::BreakpointConditionLengthType::MaxWidth,
        760.0,
        adw::LengthUnit::Sp,
    );
    let breakpoint = adw::Breakpoint::new(condition);
    breakpoint.add_setter(split, "collapsed", Some(&true.to_value()));
    breakpoint.add_setter(split, "show-sidebar", Some(&false.to_value()));
    window.add_breakpoint(breakpoint);
}

fn apply_snapshot(store: &ListStore, snap: &Snapshot) {
    let mut existing: HashMap<(u64, u64), FileRow> = HashMap::new();
    for i in 0..store.n_items() {
        if let Some(row) = store.item(i).and_downcast::<FileRow>() {
            existing.insert(row.id(), row);
        }
    }
    let mut keep = HashSet::new();
    for file in &snap.files {
        let id = (file.dev, file.ino);
        keep.insert(id);
        if let Some(row) = existing.get(&id) {
            row.apply(file);
        } else {
            let row = FileRow::new(file.dev, file.ino);
            row.apply(file);
            store.append(&row);
        }
    }
    let mut index = store.n_items();
    while index > 0 {
        index -= 1;
        if let Some(row) = store.item(index).and_downcast::<FileRow>() {
            if !keep.contains(&row.id()) {
                store.remove(index);
            }
        }
    }
}

fn show_detail(detail: &Detail, selection: &SingleSelection, procs: &Procs) {
    let Some(row) = selection.selected_item().and_downcast::<FileRow>() else {
        detail.update(None);
        return;
    };
    let procs = procs.borrow();
    let list = procs.get(&row.id()).map(Vec::as_slice).unwrap_or(&[]);
    detail.update(Some((&row, list)));
}
