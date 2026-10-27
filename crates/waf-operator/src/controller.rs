// SPDX-License-Identifier: Apache-2.0
//! The reconcile loop: watch `WafProxy` CRs and server-side-apply the owned data-plane
//! objects (ConfigMap + Deployment + Service). Owner references make deletion cascade, so
//! removing a WafProxy tears its WAF down. The rendering itself lives in `render` (pure).

use crate::crd::WafProxy;
use crate::render;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Service};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::{watcher, Controller};
use kube::{Client, ResourceExt};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

const MANAGER: &str = "waf-operator";

pub struct Context {
    pub client: Client,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube api: {0}")]
    Kube(#[from] kube::Error),
    #[error("WafProxy missing {0}")]
    Meta(&'static str),
}

async fn reconcile(wp: Arc<WafProxy>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = wp.namespace().ok_or(Error::Meta("namespace"))?;
    let name = wp.name_any();
    let uid = wp.uid().ok_or(Error::Meta("uid"))?;
    let client = &ctx.client;

    let cm = render::configmap(&name, &ns, &uid, &wp.spec);
    let dep = render::deployment(&name, &ns, &uid, &wp.spec);
    let svc = render::service(&name, &ns, &uid, &wp.spec);

    let pp = PatchParams::apply(MANAGER).force();
    let cms: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    let deps: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    let svcs: Api<Service> = Api::namespaced(client.clone(), &ns);

    cms.patch(&format!("{name}-config"), &pp, &Patch::Apply(&cm))
        .await?;
    deps.patch(&name, &pp, &Patch::Apply(&dep)).await?;
    svcs.patch(&name, &pp, &Patch::Apply(&svc)).await?;

    // Status: report that the desired objects were applied. (Actual data-plane readiness
    // — availableReplicas — is a follow-on; here `ready` means "reconciled".)
    let wps: Api<WafProxy> = Api::namespaced(client.clone(), &ns);
    let status = json!({
        "status": {
            "observedGeneration": wp.metadata.generation,
            "ready": true,
            "message": format!("applied ConfigMap/Deployment/Service for backend {}",
                wp.spec.backend_url(&ns).unwrap_or_default()),
        }
    });
    if let Err(e) = wps
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&status))
        .await
    {
        warn!(error = %e, %name, "status update failed (objects were applied)");
    }

    info!(%name, %ns, "reconciled WafProxy");
    Ok(Action::requeue(Duration::from_secs(300)))
}

fn error_policy(wp: Arc<WafProxy>, err: &Error, _ctx: Arc<Context>) -> Action {
    error!(error = %err, name = %wp.name_any(), "reconcile error; requeueing");
    Action::requeue(Duration::from_secs(30))
}

/// Run the controller until the process is stopped.
pub async fn run(client: Client) {
    let wps: Api<WafProxy> = Api::all(client.clone());
    let cms: Api<ConfigMap> = Api::all(client.clone());
    let deps: Api<Deployment> = Api::all(client.clone());
    let svcs: Api<Service> = Api::all(client.clone());

    info!("waf-operator: watching WafProxy resources");
    Controller::new(wps, watcher::Config::default())
        .owns(cms, watcher::Config::default())
        .owns(deps, watcher::Config::default())
        .owns(svcs, watcher::Config::default())
        .run(reconcile, error_policy, Arc::new(Context { client }))
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => info!(object = %obj.name, "reconcile ok"),
                Err(e) => error!(error = %e, "controller stream error"),
            }
        })
        .await;
}
