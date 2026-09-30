// SPDX-License-Identifier: MIT

mod collect;
mod model;
mod ui;

fn main() {
    if std::env::args().any(|arg| arg == "--helper") {
        std::process::exit(collect::run_helper());
    }
    if std::env::args().any(|arg| arg == "--dump") {
        std::process::exit(collect::run_dump());
    }
    ui::run();
}
