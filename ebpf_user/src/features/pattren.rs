use log::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleEvent {
    O,
    C,
    D,
}

impl SimpleEvent {
    pub fn normalize(event_type: u32) -> Option<Self> {
        match event_type {
            1 => Some(Self::O),
            3 => Some(Self::C),
            5 => Some(Self::D),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PatternCounts {
    pub ccc: u64,
    pub ccd: u64,
    pub cco: u64,
    pub cdd: u64,
    pub cdo: u64,
    pub coc: u64,
    pub cod: u64,
    pub coo: u64,
    pub dcc: u64,
    pub ddd: u64,
    pub ddo: u64,
    pub dod: u64,
    pub doo: u64,
    pub occ: u64,
    pub ocd: u64,
    pub oco: u64,
    pub odc: u64,
    pub odd: u64,
    pub odo: u64,
    pub ooc: u64,
    pub ood: u64,
    pub ooo: u64,
}

impl PatternCounts {
    pub async fn to_vec(&self) -> Vec<f32> {
        vec![
            self.ccc as f32,
            self.ccd as f32,
            self.cco as f32,
            self.cdd as f32,
            self.cdo as f32,
            self.coc as f32,
            self.cod as f32,
            self.coo as f32,
            self.dcc as f32,
            self.ddd as f32,
            self.ddo as f32,
            self.dod as f32,
            self.doo as f32,
            self.occ as f32,
            self.ocd as f32,
            self.oco as f32,
            self.odc as f32,
            self.odd as f32,
            self.odo as f32,
            self.ooc as f32,
            self.ood as f32,
            self.ooo as f32,
        ]
    }

    // This function return a tuple where the first element is the total and the second element is
    // total per time
    // Returns a tuple: (total counts, total per second)
    pub async fn total_patterns(&self, per_sec: i32) -> (f32, f32) {
        let counts = self.to_vec().await;
        let total: f32 = counts.iter().sum(); // sum of all counts
        let total_per_sec = if per_sec > 0 {
            total / per_sec as f32 // normalized per second
        } else {
            0.0
        };
        (total, total_per_sec)
    }
}

impl std::fmt::Display for PatternCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "PatternCounts {{")?;
        writeln!(f, "    ccc: {},  // Close → Close → Close", self.ccc)?;
        writeln!(f, "    ccd: {},  // Close → Close → Delete", self.ccd)?;
        writeln!(f, "    cco: {},  // Close → Close → Open", self.cco)?;
        writeln!(f, "    cdd: {},  // Close → Delete → Delete", self.cdd)?;
        writeln!(f, "    cdo: {},  // Close → Delete → Open", self.cdo)?;
        writeln!(f, "    coc: {},  // Close → Open → Close", self.coc)?;
        writeln!(f, "    cod: {},  // Close → Open → Delete", self.cod)?;
        writeln!(f, "    coo: {},  // Close → Open → Open", self.coo)?;
        writeln!(f, "    dcc: {},  // Delete → Close → Close", self.dcc)?;
        writeln!(f, "    ddd: {},  // Delete → Delete → Delete", self.ddd)?;
        writeln!(f, "    ddo: {},  // Delete → Delete → Open", self.ddo)?;
        writeln!(f, "    dod: {},  // Delete → Open → Delete", self.dod)?;
        writeln!(f, "    doo: {},  // Delete → Open → Open", self.doo)?;
        writeln!(f, "    occ: {},  // Open → Close → Close", self.occ)?;
        writeln!(f, "    ocd: {},  // Open → Close → Delete", self.ocd)?;
        writeln!(f, "    oco: {},  // Open → Close → Open", self.oco)?;
        writeln!(f, "    odc: {},  // Open → Delete → Close", self.odc)?;
        writeln!(f, "    odd: {},  // Open → Delete → Delete", self.odd)?;
        writeln!(f, "    odo: {},  // Open → Delete → Open", self.odo)?;
        writeln!(f, "    ooc: {},  // Open → Open → Close", self.ooc)?;
        writeln!(f, "    ood: {},  // Open → Open → Delete", self.ood)?;
        writeln!(f, "    ooo: {},  // Open → Open → Open", self.ooo)?;
        write!(f, "}}")
    }
}

pub fn update_pattern(counts: &mut PatternCounts, p: &[SimpleEvent]) {
    use SimpleEvent::*;
    match p {
        [C, C, C] => counts.ccc += 1,
        [C, C, D] => counts.ccd += 1,
        [C, C, O] => counts.cco += 1,
        [C, D, D] => counts.cdd += 1,
        [C, D, O] => counts.cdo += 1,
        [C, O, C] => counts.coc += 1,
        [C, O, D] => counts.cod += 1,
        [C, O, O] => counts.coo += 1,
        [D, C, C] => counts.dcc += 1,
        [D, D, D] => counts.ddd += 1,
        [D, D, O] => counts.ddo += 1,
        [D, O, D] => counts.dod += 1,
        [D, O, O] => counts.doo += 1,
        [O, C, C] => counts.occ += 1,
        [O, C, D] => counts.ocd += 1,
        [O, C, O] => counts.oco += 1,
        [O, D, C] => counts.odc += 1,
        [O, D, D] => counts.odd += 1,
        [O, D, O] => counts.odo += 1,
        [O, O, C] => counts.ooc += 1,
        [O, O, D] => counts.ood += 1,
        [O, O, O] => counts.ooo += 1,
        _ => warn!("Unknown pattern {:?}", p),
    }
}
