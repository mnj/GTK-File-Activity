// SPDX-License-Identifier: MIT

//! The 60 second read and write history.

use crate::model::{format_rate, GraphPoint};
use gtk::cairo::{Context, LinearGradient};
use gtk::prelude::*;
use gtk::{Align, DrawingArea, Label, Overlay};
use libadwaita as adw;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

const WINDOW_SECS: f64 = 60.0;

struct Palette {
    read: (f64, f64, f64),
    write: (f64, f64, f64),
}

impl Palette {
    fn current() -> Self {
        if adw::StyleManager::default().is_dark() {
            Self {
                read: (0.384, 0.627, 0.918),
                write: (1.0, 0.639, 0.282),
            }
        } else {
            Self {
                read: (0.110, 0.443, 0.847),
                write: (0.902, 0.380, 0.0),
            }
        }
    }
}

#[derive(Clone)]
pub struct Graph {
    pub widget: Overlay,
    area: DrawingArea,
    points: Rc<RefCell<Vec<GraphPoint>>>,
    scale: Rc<Cell<f64>>,
    max_label: Label,
}

impl Graph {
    pub fn new() -> Self {
        let points: Rc<RefCell<Vec<GraphPoint>>> = Rc::default();
        let scale = Rc::new(Cell::new(nice_max(0.0)));
        let area = DrawingArea::builder()
            .content_height(96)
            .hexpand(true)
            .build();
        {
            let points = points.clone();
            let scale = scale.clone();
            area.set_draw_func(move |area, cr, width, height| {
                let fg = area.color();
                let fg = (fg.red() as f64, fg.green() as f64, fg.blue() as f64);
                draw(cr, width as f64, height as f64, &points.borrow(), scale.get(), fg);
            });
        }
        {
            let area = area.clone();
            adw::StyleManager::default().connect_dark_notify(move |_| area.queue_draw());
        }

        let overlay = Overlay::new();
        overlay.set_child(Some(&area));
        let max_label = corner_label(Align::Start, Align::Start);
        overlay.add_overlay(&max_label);
        overlay.add_overlay(&corner_label_text("60 s ago", Align::Start, Align::End));
        overlay.add_overlay(&corner_label_text("now", Align::End, Align::End));
        max_label.set_label(&format_rate(scale.get()));
        Self {
            widget: overlay,
            area,
            points,
            scale,
            max_label,
        }
    }

    pub fn update(&self, points: Vec<GraphPoint>) {
        let peak = points
            .iter()
            .map(|p| p.read_bps.max(p.write_bps))
            .fold(0.0, f64::max);
        let max = nice_max(peak);
        self.scale.set(max);
        self.max_label.set_label(&format_rate(max));
        *self.points.borrow_mut() = points;
        self.area.queue_draw();
    }
}

fn corner_label(h: Align, v: Align) -> Label {
    let label = Label::builder()
        .halign(h)
        .valign(v)
        .margin_start(10)
        .margin_end(10)
        .margin_top(6)
        .margin_bottom(4)
        .can_target(false)
        .build();
    label.add_css_class("caption");
    label.add_css_class("dim-label");
    label.add_css_class("numeric");
    label
}

fn corner_label_text(text: &str, h: Align, v: Align) -> Label {
    let label = corner_label(h, v);
    label.set_label(text);
    label
}

/// The next power of two at or above the peak, with some headroom, and never
/// below 1 KiB/s so an idle graph has a steady scale.
pub fn nice_max(peak: f64) -> f64 {
    let target = (peak * 1.1).max(1024.0);
    2f64.powf(target.log2().ceil())
}

fn draw(cr: &Context, w: f64, h: f64, points: &[GraphPoint], max: f64, fg: (f64, f64, f64)) {
    if w < 4.0 || h < 4.0 {
        return;
    }
    cr.set_line_width(1.0);
    for k in 0..4 {
        let y = (h - 1.0) * k as f64 / 3.0 + 0.5;
        cr.set_source_rgba(fg.0, fg.1, fg.2, if k == 3 { 0.25 } else { 0.10 });
        cr.move_to(0.0, y);
        cr.line_to(w, y);
        let _ = cr.stroke();
    }
    if points.len() < 2 {
        return;
    }
    let palette = Palette::current();
    let x = |age: f64| (WINDOW_SECS - age.clamp(0.0, WINDOW_SECS)) / WINDOW_SECS * w;
    let y = |value: f64| h - 1.0 - (value / max).min(1.0) * (h - 10.0);
    series(cr, points, &x, &y, |p| p.read_bps, palette.read, h);
    series(cr, points, &x, &y, |p| p.write_bps, palette.write, h);
}

fn series(
    cr: &Context,
    points: &[GraphPoint],
    x: &impl Fn(f64) -> f64,
    y: &impl Fn(f64) -> f64,
    value: impl Fn(&GraphPoint) -> f64,
    (r, g, b): (f64, f64, f64),
    h: f64,
) {
    let trace = |cr: &Context| {
        for (i, point) in points.iter().enumerate() {
            let (px, py) = (x(point.age), y(value(point)));
            if i == 0 {
                cr.move_to(px, py);
            } else {
                cr.line_to(px, py);
            }
        }
    };
    trace(cr);
    cr.line_to(x(points[points.len() - 1].age), h);
    cr.line_to(x(points[0].age), h);
    cr.close_path();
    let fill = LinearGradient::new(0.0, 0.0, 0.0, h);
    fill.add_color_stop_rgba(0.0, r, g, b, 0.28);
    fill.add_color_stop_rgba(1.0, r, g, b, 0.02);
    let _ = cr.set_source(&fill);
    let _ = cr.fill();

    trace(cr);
    cr.set_source_rgb(r, g, b);
    cr.set_line_width(2.0);
    cr.set_line_join(gtk::cairo::LineJoin::Round);
    let _ = cr.stroke();
}

#[cfg(test)]
mod tests {
    use super::nice_max;

    #[test]
    fn scale_has_a_floor_and_grows_in_powers_of_two() {
        assert_eq!(nice_max(0.0), 1024.0);
        assert_eq!(nice_max(900.0), 1024.0);
        assert_eq!(nice_max(1000.0), 2048.0);
        assert_eq!(nice_max(3.0 * 1024.0 * 1024.0), 4.0 * 1024.0 * 1024.0);
    }
}
