// SPDX-License-Identifier: Apache-2.0
//! waf-operator binary.
//!
//!   waf-operator          run the controller (needs a kubeconfig / in-cluster SA)
//!   waf-operator crd      print the WafProxy CRD YAML (for `kubectl apply -f -`)

use kube::{Client, CustomResourceExt};
use tracing_subscriber::EnvFilter;
use waf_operator::{controller, WafProxy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("crd") {
        // Emit the CRD manifest (no cluster needed).
        print!("{}", serde_yaml::to_string(&WafProxy::crd())?);
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let client = Client::try_default().await?;
    controller::run(client).await;
    Ok(())
}
