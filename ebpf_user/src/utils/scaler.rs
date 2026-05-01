use serde::Deserialize;
use serde_json;
use std::{fs, path::PathBuf};
#[derive(Deserialize)]
pub struct Scaler {
    pub mean: Vec<f32>,
    pub scale: Vec<f32>,
}

impl Scaler {
    pub fn new(scale_path: PathBuf) -> Self {
        let file_content = fs::read_to_string(scale_path).unwrap();
        serde_json::from_str(&file_content).unwrap()
    }

    pub fn scaled_data(&mut self, vector: &mut [f32]) {
        assert_eq!(vector.len(), self.mean.len());
        for (index, elem) in vector.iter_mut().enumerate() {
            *elem = (*elem - self.mean[index]) / self.scale[index];
        }
    }
}
