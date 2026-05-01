use std::sync::{Arc, Mutex};

pub struct RingBuffer<T> {
    inner: Vec<T>,
}

impl<T> RingBuffer<T> {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    pub fn push(&mut self, item: T) {
        self.inner.push(item);
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.inner.is_empty() {
            None
        } else {
            Some(self.inner.remove(0))
        }
    }
}

pub type SharedRingBuffer<T> = Arc<Mutex<RingBuffer<T>>>;
