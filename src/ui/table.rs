// SPDX-License-Identifier: MIT

//! The file list.

use super::row::{split_path, FileRow};
use crate::model::format_rate;
use gtk::gio;
use gtk::pango::EllipsizeMode;
use gtk::prelude::*;
use gtk::{
    Align, ColumnView, ColumnViewColumn, Image, Label, ListItem, NumericSorter, Orientation,
    PropertyExpression, SignalListItemFactory, SingleSelection, SortType, StringSorter, Widget,
};

pub fn build(selection: &SingleSelection) -> ColumnView {
    let view = ColumnView::builder()
        .model(selection)
        .hexpand(true)
        .vexpand(true)
        .build();
    view.add_css_class("data-table");

    add_column(
        &view,
        "File",
        true,
        Some(string_sorter("path").upcast()),
        file_cell,
        bind_file,
    );
    add_column(
        &view,
        "Read",
        false,
        Some(numeric_sorter("read-bps").upcast()),
        || rate_cell("read-rate"),
        |row, w| set_rate(w, row.read_bps()),
    );
    add_column(
        &view,
        "Write",
        false,
        Some(numeric_sorter("write-bps").upcast()),
        || rate_cell("write-rate"),
        |row, w| set_rate(w, row.write_bps()),
    );
    let total = add_column(
        &view,
        "Total",
        false,
        Some(numeric_sorter("total-bps").upcast()),
        || rate_cell(""),
        |row, w| set_rate(w, row.total_bps()),
    );
    add_column(&view, "Ops (r / w)", false, None, dim_cell, |row, w| {
        if let Some(label) = w.downcast_ref::<Label>() {
            label.set_text(&row.ops());
        }
    });
    add_column(
        &view,
        "Processes",
        true,
        Some(string_sorter("summary").upcast()),
        text_cell,
        |row, w| {
            if let Some(label) = w.downcast_ref::<Label>() {
                label.set_text(&row.summary());
                label.set_tooltip_text(Some(&row.summary()));
            }
        },
    );
    view.sort_by_column(Some(&total), SortType::Descending);
    view
}

fn add_column(
    view: &ColumnView,
    title: &str,
    expand: bool,
    sorter: Option<gtk::Sorter>,
    make: impl Fn() -> Widget + 'static,
    bind: impl Fn(&FileRow, &Widget) + 'static,
) -> ColumnViewColumn {
    let factory = SignalListItemFactory::new();
    factory.connect_setup(move |_, obj| {
        if let Some(item) = obj.downcast_ref::<ListItem>() {
            item.set_child(Some(&make()));
        }
    });
    factory.connect_bind(move |_, obj| {
        let Some(item) = obj.downcast_ref::<ListItem>() else {
            return;
        };
        let (Some(row), Some(child)) = (item.item().and_downcast::<FileRow>(), item.child())
        else {
            return;
        };
        bind(&row, &child);
    });
    let column = ColumnViewColumn::new(Some(title), Some(factory));
    column.set_expand(expand);
    column.set_resizable(true);
    if let Some(sorter) = sorter {
        column.set_sorter(Some(&sorter));
    }
    view.append_column(&column);
    column
}

fn text_cell() -> Widget {
    Label::builder()
        .xalign(0.0)
        .ellipsize(EllipsizeMode::Middle)
        .build()
        .upcast()
}

fn dim_cell() -> Widget {
    let label = Label::builder().xalign(1.0).build();
    label.add_css_class("numeric");
    label.add_css_class("dim-label");
    label.upcast()
}

fn rate_cell(class: &str) -> Widget {
    let label = Label::builder().xalign(1.0).build();
    label.add_css_class("numeric");
    if !class.is_empty() {
        label.add_css_class(class);
    }
    label.upcast()
}

fn set_rate(widget: &Widget, bps: f64) {
    let Some(label) = widget.downcast_ref::<Label>() else {
        return;
    };
    if bps < 0.5 {
        label.set_text("—");
        label.set_opacity(0.35);
    } else {
        label.set_text(&format_rate(bps));
        label.set_opacity(1.0);
    }
}

/// Icon, file name and, beneath it, the folder.
fn file_cell() -> Widget {
    let icon = Image::builder().pixel_size(16).valign(Align::Center).build();
    let name = Label::builder()
        .xalign(0.0)
        .ellipsize(EllipsizeMode::End)
        .build();
    name.add_css_class("file-name");
    let dir = Label::builder()
        .xalign(0.0)
        .ellipsize(EllipsizeMode::Start)
        .build();
    dir.add_css_class("caption");
    dir.add_css_class("dim-label");
    let text = gtk::Box::new(Orientation::Vertical, 0);
    text.set_hexpand(true);
    text.append(&name);
    text.append(&dir);
    let cell = gtk::Box::new(Orientation::Horizontal, 10);
    cell.append(&icon);
    cell.append(&text);
    cell.upcast()
}

fn bind_file(row: &FileRow, widget: &Widget) {
    let Some(cell) = widget.downcast_ref::<gtk::Box>() else {
        return;
    };
    let Some(icon) = cell.first_child().and_downcast::<Image>() else {
        return;
    };
    let Some(text) = icon.next_sibling().and_downcast::<gtk::Box>() else {
        return;
    };
    let Some(name) = text.first_child().and_downcast::<Label>() else {
        return;
    };
    let Some(dir) = name.next_sibling().and_downcast::<Label>() else {
        return;
    };
    let path = row.path();
    let (file, folder) = split_path(&path);
    name.set_text(file);
    dir.set_text(folder);
    dir.set_visible(!folder.is_empty());
    cell.set_tooltip_text(Some(&path));
    let (content_type, _) = gio::content_type_guess(Some(file), &[]);
    icon.set_from_gicon(&gio::content_type_get_symbolic_icon(&content_type));
}

fn numeric_sorter(prop: &str) -> NumericSorter {
    let expr = PropertyExpression::new(FileRow::static_type(), None::<gtk::Expression>, prop);
    NumericSorter::builder().expression(&expr).build()
}

fn string_sorter(prop: &str) -> StringSorter {
    let expr = PropertyExpression::new(FileRow::static_type(), None::<gtk::Expression>, prop);
    StringSorter::builder().expression(&expr).build()
}
