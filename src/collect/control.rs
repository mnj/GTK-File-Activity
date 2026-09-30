// SPDX-License-Identifier: MIT

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Settings the UI shares with the sampling thread.
pub struct Control {
    interval: Mutex<Duration>,
    pub paused: AtomicBool,
    pub show_idle: AtomicBool,
    stop: AtomicBool,
    want_helper: AtomicBool,
    lock: Mutex<()>,
    cv: Condvar,
}

impl Control {
    pub fn new(interval: Duration, show_idle: bool) -> Arc<Self> {
        Arc::new(Self {
            interval: Mutex::new(interval),
            paused: AtomicBool::new(false),
            show_idle: AtomicBool::new(show_idle),
            stop: AtomicBool::new(false),
            want_helper: AtomicBool::new(false),
            lock: Mutex::new(()),
            cv: Condvar::new(),
        })
    }

    pub fn interval(&self) -> Duration {
        *self.interval.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_interval(&self, interval: Duration) {
        *self.interval.lock().unwrap_or_else(|e| e.into_inner()) = interval;
        self.notify();
    }

    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
        self.notify();
    }

    pub fn set_show_idle(&self, show: bool) {
        self.show_idle.store(show, Ordering::SeqCst);
        self.notify();
    }

    /// Ask the sampling thread to start the privileged helper.
    pub fn request_helper(&self) {
        self.want_helper.store(true, Ordering::SeqCst);
        self.notify();
    }

    pub(super) fn take_helper_request(&self) -> bool {
        self.want_helper.swap(false, Ordering::SeqCst)
    }

    pub fn show_idle(&self) -> bool {
        self.show_idle.load(Ordering::SeqCst)
    }

    pub fn notify(&self) {
        self.cv.notify_all();
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.notify();
    }

    pub(super) fn wait(&self, dur: Duration) {
        let guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.cv.wait_timeout(guard, dur);
    }

    pub(super) fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub(super) fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }
}
