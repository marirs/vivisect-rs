#![allow(dead_code, unused)]

///  Emulation monitors may be passed into functions like
///  runFunction() to track and hook the emulator.
#[derive(Clone, Debug)]
pub struct EmulationMonitor {
    emulation_anomalies: Vec<(i32, String)>,
    return_values: Vec<String>,
}

impl EmulationMonitor {
    pub fn new() -> Self {
        EmulationMonitor {
            emulation_anomalies: Vec::new(),
            return_values: Vec::new(),
        }
    }

    pub fn log_anomaly(&mut self, va: i32, msg: String) {
        self.emulation_anomalies.push((va, msg));
    }

    pub fn get_anomalies(&mut self) -> Vec<(i32, String)> {
        self.emulation_anomalies.clone()
    }
}
