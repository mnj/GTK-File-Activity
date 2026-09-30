// SPDX-License-Identifier: MIT

use crate::model::FileSnapshot;
use gtk::glib::{self, Properties};
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use std::cell::{Cell, RefCell};

mod imp {
    use super::*;

    #[derive(Default, Properties)]
    #[properties(wrapper_type = super::FileRow)]
    pub struct FileRow {
        #[property(get, set)]
        pub path: RefCell<String>,
        #[property(get, set)]
        pub summary: RefCell<String>,
        #[property(get, set)]
        pub ops: RefCell<String>,
        #[property(get, set)]
        pub haystack: RefCell<String>,
        #[property(get, set)]
        pub read_bps: Cell<f64>,
        #[property(get, set)]
        pub write_bps: Cell<f64>,
        #[property(get, set)]
        pub total_bps: Cell<f64>,
        #[property(get, set)]
        pub dev: Cell<u64>,
        #[property(get, set)]
        pub ino: Cell<u64>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for FileRow {
        const NAME: &'static str = "GfaFileRow";
        type Type = super::FileRow;
    }

    #[glib::derived_properties]
    impl ObjectImpl for FileRow {}
}

glib::wrapper! {
    pub struct FileRow(ObjectSubclass<imp::FileRow>);
}

impl FileRow {
    pub fn new(dev: u64, ino: u64) -> Self {
        glib::Object::builder()
            .property("dev", dev)
            .property("ino", ino)
            .build()
    }

    pub fn id(&self) -> (u64, u64) {
        (self.dev(), self.ino())
    }

    pub fn apply(&self, file: &FileSnapshot) {
        self.set_path(file.path.clone());
        self.set_summary(if file.summary.is_empty() {
            "—".to_string()
        } else {
            file.summary.clone()
        });
        self.set_ops(format!("{} / {}", file.reads, file.writes));
        self.set_haystack(file.haystack.clone());
        self.set_read_bps(file.read_bps);
        self.set_write_bps(file.write_bps);
        self.set_total_bps(file.read_bps + file.write_bps);
    }
}

/// Splits a path into the name to show large and the folder to show small.
pub fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => (&path[1..], "/"),
        Some(at) if at + 1 < path.len() => (&path[at + 1..], &path[..at]),
        _ => (path, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::split_path;

    #[test]
    fn splits_names_from_folders() {
        assert_eq!(split_path("/home/me/notes.txt"), ("notes.txt", "/home/me"));
        assert_eq!(split_path("/swapfile"), ("swapfile", "/"));
        assert_eq!(split_path("8:1 inode 12"), ("8:1 inode 12", ""));
        assert_eq!(split_path("/tmp/x (deleted)"), ("x (deleted)", "/tmp"));
    }
}
