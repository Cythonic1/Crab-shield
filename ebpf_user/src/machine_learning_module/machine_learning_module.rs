use std::{collections::HashMap, path::PathBuf, str::FromStr};

use log::{info, warn};
use ndarray::Array2;
use ort::{
    memory::Allocator,
    session::{Session, SessionOutputs},
    value::{DynValueTypeMarker, Value},
};

use crate::{
    alert::handler_alert::AlertManager,
    features::{features::Features, pattren::PatternCounts},
    machine_learning_module::AlertingInfo,
    utils::scaler::Scaler,
};

const FEATURE_COUNT: usize = 31; // Number of the feature arguments

#[allow(dead_code)]
pub struct ModuleFeatures {
    module: Session,
    to_be_alert: Vec<AlertingInfo>,
    scaler: Scaler,
    alert_client: AlertManager,
}

impl ModuleFeatures {
    pub fn new(
        machine_learning_module_path: String,
        data_scal_path: String,
        alert_client: AlertManager,
    ) -> Self {
        match ort::init().commit() {
            true => {
                info!("Module configuration has been loaded");
            }
            false => {
                warn!("Failed to load module configuration")
            }
        }

        let scaler = Scaler::new(
            PathBuf::from_str(&data_scal_path).expect("Unable to convert String into PathBuf"),
        );

        let session = ort::session::Session::builder()
            .expect("Error buiding session")
            .commit_from_file(machine_learning_module_path)
            .expect("Error init session");

        ModuleFeatures {
            to_be_alert: Vec::new(),
            module: session,
            alert_client,
            scaler,
        }
    }

    async fn check_output_module(outputs: SessionOutputs<'_>, pid: &u32) -> AlertingInfo {
        let prediction = outputs["output_label"]
            .try_extract_tensor::<i64>()
            .expect("Error shaping");
        let pred_class = prediction.0[0];
        let allocator = Allocator::default();

        let probabilities = outputs["output_probability"]
            .try_extract_sequence::<DynValueTypeMarker>(&allocator)
            .expect("Error getting the map");

        // Extract the map for the first prediction
        if let Some(prob_map) = probabilities.first() {
            let map = prob_map
                .try_extract_map::<i64, f32>()
                .expect("Error find the map value");

            // Get probability for class 0 and class 1
            let prob_class0 = map.get(&0).unwrap_or(&0.0);
            let prob_class1 = map.get(&1).unwrap_or(&0.0);

            println!("Prediction: {}", pred_class);
            println!("Probability(class=0): {:.2}%", prob_class0 * 100.0);
            println!("Probability(class=1): {:.2}%", prob_class1 * 100.0);
            AlertingInfo(*pid, prob_class1 * 100.0)
        } else {
            AlertingInfo(0, 0.0)
        }
    }

    pub async fn module_check(&mut self, processes: &HashMap<u32, Features>) {
        for (pid, features) in processes {
            let mut ml_data = Self::prepare_data(features, features.pattern).await;
            Self::print_data(ml_data.clone()).await;

            self.scaler.scaled_data(&mut ml_data);
            assert_eq!(ml_data.len(), FEATURE_COUNT);
            let input = Array2::from_shape_vec((1, FEATURE_COUNT), ml_data)
                .expect("Error shaping the data");

            // Run inference
            let input_value = Value::from_array(input).expect("Error input value");

            let outputs = self
                .module
                .run(ort::inputs!["X" => input_value])
                .expect("Error getting the output from the module");

            let predect_res = Self::check_output_module(outputs, pid).await;
            if predect_res.1 == 0.0 && predect_res.0 == 0 {
                warn!("Faild to parse module output not will not send alert");
                return;
            }
            self.alert_client.send_alert(predect_res).await;

            info!("Finish output for prcoess {}", pid);
        }
    }

    // Now the vector looks like this
    // ( close_syscalls, open_syscalls,delete_syscall,pattren_total, pattren_per, entropy ,CCC,CCD,CCO,CDD,CDO,COC,COD,COO,DCC,DDD,DDO,DOD,DOO,OCC,OCD,OCO,ODC,ODD,ODO,OOC,OOD,OOO, per_close,per_open, per_delete)
    async fn prepare_data(features: &Features, pattent: PatternCounts) -> Vec<f32> {
        let mut vec_data = features.to_vec_to_ml();
        let pattrent_sum_per = pattent.total_patterns(10).await;
        vec_data.push(pattrent_sum_per.0);
        vec_data.push(pattrent_sum_per.1);
        let pattren_vec = pattent.to_vec().await;
        vec_data.extend(pattren_vec);
        let per_data = Self::calculate_per_data(10, &vec_data[0..3]).await;
        vec_data.extend(per_data);

        Self::reorder_for_ml(vec_data)
    }

    //This function calcualte the number of event per <some time frame> time frame should
    //only be in seconds
    // return data going to look like this.
    // (close_syscalls, open_syscalls,delete_syscall, entropy)
    // We going to handle only the first three.
    async fn calculate_per_data(time_frame: i32, features: &[f32]) -> Vec<f32> {
        let mut per_data = Vec::new();
        for elem in features.iter() {
            let per = elem / time_frame as f32;
            per_data.push(per);
        }
        per_data
    }

    async fn print_data(data: Vec<f32>) {
        let field_names = [
            // Syscall max + per
            "close_syscalls_max",  // c_max
            "per_close",           // c_sum
            "open_syscalls_max",   // d_max
            "per_open",            // d_sum
            "delete_syscalls_max", // o_max
            "per_delete",          // o_sum
            // Pattern totals
            "pattern_total_max", // p_max
            "pattern_total_per", // p_sum
            // Pattern counts (EXACT original order 6..27)
            "CCC",
            "CCD",
            "CCO",
            "CDD",
            "CDO",
            "COC",
            "COD",
            "COO",
            "DCC",
            "DDD",
            "DDO",
            "DOD",
            "DOO",
            "OCC",
            "OCD",
            "OCO",
            "ODC",
            "ODD",
            "ODO",
            "OOC",
            "OOD",
            "OOO",
            // Entropy
            "entropy",
        ];

        assert_eq!(data.len(), field_names.len());

        for (i, (name, value)) in field_names.iter().zip(data.iter()).enumerate() {
            println!("{:02} {:<24} {}", i, name, value);
        }
    }
    pub fn reorder_for_ml(vec_data: Vec<f32>) -> Vec<f32> {
        assert_eq!(vec_data.len(), FEATURE_COUNT);
        let mut reordered = Vec::with_capacity(vec_data.len());

        // Map syscalls and per-values
        let c_max = vec_data[0]; // close_syscalls
        let d_max = vec_data[1]; // open_syscalls
        let o_max = vec_data[2]; // delete_syscall
        let entropy = vec_data[3]; // entropy
        let p_max = vec_data[4]; // pattern_total

        let p_sum = vec_data[5]; // pattern_per

        let pattern_counts = &vec_data[6..28]; // CCC..OOO

        let c_sum = vec_data[28]; // per_close
        let d_sum = vec_data[29]; // per_open
        let o_sum = vec_data[30]; // per_delete

        // Push in ML order
        reordered.push(c_max);
        reordered.push(c_sum);
        reordered.push(d_max);
        reordered.push(d_sum);
        reordered.push(o_max);
        reordered.push(o_sum);
        reordered.push(p_max);
        reordered.push(p_sum);

        // Pattern counts
        reordered.extend_from_slice(pattern_counts);

        // Entropy
        reordered.push(entropy);

        reordered
    }
}
