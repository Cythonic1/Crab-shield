use std::collections::HashMap;

use log::info;

#[derive(Debug, Clone, Default)]
pub struct Entropy {
    frequents: HashMap<u8, usize>,
}

impl Entropy {
    pub fn new() -> Entropy {
        Entropy {
            frequents: HashMap::new(),
        }
    }

    pub fn clean(&mut self) {
        self.frequents = HashMap::new();
    }

    // Make this function return only the entropy_value
    pub async fn calculate_entropy(&mut self, buf: Vec<u8>) -> f32 {
        self.clean();
        self.contruct_hash_map(&buf);
        let mut entropy = 0.0;
        for freq in self.frequents.values() {
            let p = *freq as f64 / buf.len() as f64;
            if p > 0.0 {
                entropy += -p * p.log2();
            }
        }

        // Return entropy but not tested yet
        info!("Finish calculating entropy for a size of {}", buf.len());
        entropy as f32
    }

    fn contruct_hash_map(&mut self, buf: &[u8]) {
        if buf.is_empty() {
            println!("Make sure to read first");
            return;
        }
        for byte in buf.iter() {
            self.frequents
                .entry(*byte)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
    }
}
