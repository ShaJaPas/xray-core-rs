use std::sync::Arc;

use xray_core_rs::core::{config::Config, service::Service};

static mut SERVICE: Option<Service> = None;

#[tokio::main]
async fn main() {
    let file = include_str!("config.json");
    let config = Arc::new(serde_json::from_str(file).unwrap());
    unsafe { 
        let _ = SERVICE.insert(Service::new_from_config(config).await);
        SERVICE.as_ref().unwrap().run().await 
    }
}