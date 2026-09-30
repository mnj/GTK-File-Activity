// SPDX-License-Identifier: MIT

//! The sidebar: the selected file and the processes using it.

use super::row::{split_path, FileRow};
use crate::model::{format_rate, ProcSnapshot};
use gtk::gio;
use gtk::pango::WrapMode;
use gtk::prelude::*;
use gtk::{Align, Box, Button, Label, ListBox, Orientation, ScrolledWindow, Stack};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
pub struct Detail {
    pub widget: Stack,
    name: Label,
    path: Label,
    read: Label,
    write: Label,
    list: ListBox,
    current: Rc<RefCell<String>>,
    actions: Box,
}

impl Detail {
    pub fn new() -> Self {
        let placeholder = adw::StatusPage::builder()
            .icon_name("document-properties-symbolic")
            .title("No File Selected")
            .description("Select a file to see which processes are using it.")
            .build();
        placeholder.add_css_class("compact");

        let name = Label::builder()
            .xalign(0.0)
            .wrap(true)
            .wrap_mode(WrapMode::WordChar)
            .selectable(true)
            .build();
        name.add_css_class("title-3");
        let path = Label::builder()
            .xalign(0.0)
            .wrap(true)
            .wrap_mode(WrapMode::WordChar)
            .selectable(true)
            .build();
        path.add_css_class("caption");
        path.add_css_class("dim-label");

        let read = rate_label("read-rate");
        let write = rate_label("write-rate");
        let rates = Box::new(Orientation::Horizontal, 18);
        rates.append(&read);
        rates.append(&write);

        let current = Rc::new(RefCell::new(String::new()));
        let copy = Button::with_label("Copy Path");
        let show = Button::with_label("Show in Files");
        {
            let current = current.clone();
            copy.connect_clicked(move |button| {
                button.clipboard().set_text(&current.borrow());
            });
        }
        {
            let current = current.clone();
            show.connect_clicked(move |button| {
                let file = gio::File::for_path(&*current.borrow());
                let window = button.root().and_downcast::<gtk::Window>();
                gtk::FileLauncher::new(Some(&file)).open_containing_folder(
                    window.as_ref(),
                    gio::Cancellable::NONE,
                    |_| {},
                );
            });
        }
        let actions = Box::new(Orientation::Horizontal, 6);
        actions.append(&copy);
        actions.append(&show);

        let heading = Label::builder()
            .label("Processes")
            .xalign(0.0)
            .margin_top(6)
            .build();
        heading.add_css_class("heading");
        let list = ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        list.add_css_class("boxed-list");

        let body = Box::new(Orientation::Vertical, 10);
        body.set_margin_top(14);
        body.set_margin_bottom(14);
        body.set_margin_start(14);
        body.set_margin_end(14);
        body.append(&name);
        body.append(&path);
        body.append(&rates);
        body.append(&actions);
        body.append(&heading);
        body.append(&list);
        let scroll = ScrolledWindow::builder()
            .child(&body)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build();

        let widget = Stack::new();
        widget.add_named(&placeholder, Some("empty"));
        widget.add_named(&scroll, Some("file"));
        Self {
            widget,
            name,
            path,
            read,
            write,
            list,
            current,
            actions,
        }
    }

    pub fn update(&self, selected: Option<(&FileRow, &[ProcSnapshot])>) {
        let Some((row, procs)) = selected else {
            self.widget.set_visible_child_name("empty");
            return;
        };
        let full = row.path();
        let (file, folder) = split_path(&full);
        self.name.set_label(file);
        self.path.set_label(if folder.is_empty() { "" } else { &full });
        self.path.set_visible(!folder.is_empty());
        self.read.set_label(&format!("↓ {}", format_rate(row.read_bps())));
        self.write.set_label(&format!("↑ {}", format_rate(row.write_bps())));
        self.actions
            .set_sensitive(full.starts_with('/') && !full.contains(" (deleted)"));
        *self.current.borrow_mut() = full;

        while let Some(child) = self.list.first_child() {
            self.list.remove(&child);
        }
        if procs.is_empty() {
            let none = adw::ActionRow::new();
            none.set_title("No process attached in this sample");
            none.add_css_class("dim-label");
            self.list.append(&none);
        }
        for proc in procs {
            self.list.append(&process_row(proc));
        }
        self.widget.set_visible_child_name("file");
    }
}

fn rate_label(class: &str) -> Label {
    let label = Label::builder().xalign(0.0).build();
    label.add_css_class("numeric");
    label.add_css_class("title-4");
    label.add_css_class(class);
    label
}

fn process_row(proc: &ProcSnapshot) -> adw::ActionRow {
    let exe = proc.comm.as_str();
    let name = exe.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or(exe);
    let row = adw::ActionRow::new();
    row.set_use_markup(false);
    row.set_title(name);
    row.set_subtitle(&meta(proc));
    row.set_tooltip_text(Some(exe));

    let read = Label::builder()
        .label(format!("↓ {}", format_rate(proc.read_bps)))
        .xalign(1.0)
        .build();
    read.add_css_class("read-rate");
    let write = Label::builder()
        .label(format!("↑ {}", format_rate(proc.write_bps)))
        .xalign(1.0)
        .build();
    write.add_css_class("write-rate");
    let rates = Box::new(Orientation::Vertical, 0);
    rates.set_valign(Align::Center);
    for label in [&read, &write] {
        label.add_css_class("numeric");
        label.add_css_class("caption");
        rates.append(label);
    }
    row.add_suffix(&rates);
    row
}

fn meta(proc: &ProcSnapshot) -> String {
    let fds = match proc.fds.len() {
        0 => "fd closed".to_string(),
        1..=6 => format!("fd {}", join(&proc.fds)),
        n => format!("fd {} +{}", join(&proc.fds[..6]), n - 6),
    };
    let state = match (proc.did_io, proc.still_open) {
        (true, true) => "active, open",
        (true, false) => "active, closed",
        (false, true) => "open, idle",
        (false, false) => "idle",
    };
    format!(
        "pid {} · {fds} · {state} · {} / {} ops",
        proc.tgid, proc.reads, proc.writes
    )
}

fn join(fds: &[i32]) -> String {
    fds.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
