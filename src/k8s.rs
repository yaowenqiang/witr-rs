//! Kubernetes pod attribution: match containers to their owning pods via
//! one `kubectl get pods -A -o json` call. Best effort throughout — no
//! kubectl, no cluster access, or simply not-a-k8s-container all leave the
//! pod field empty. The pod list is probed once per process (a missing
//! cluster won't appear mid-run, and the TUI re-annotates on each
//! containers refresh of a fresh process anyway).

use serde::Serialize;
use std::sync::OnceLock;

use crate::model::Container;

/// Minimal pod identity: "namespace/name" + the runtime container ids as
/// kubectl reports them ("docker://<64hex>", "containerd://<hex>", ...).
#[derive(Debug, Clone, Serialize)]
pub struct Pod {
    pub key: String,
    pub container_ids: Vec<String>,
}

/// All pods visible to the current context. None once the probe has failed
/// (kubectl missing / cluster unreachable), cached for the process
/// lifetime.
pub fn pods() -> Option<Vec<Pod>> {
    static CACHE: OnceLock<Option<Vec<Pod>>> = OnceLock::new();
    if let Some(cached) = CACHE.get() {
        return cached.clone();
    }
    let out = (|| {
        let text = crate::util::run(
            "kubectl",
            &["get", "pods", "-A", "-o", "json"],
            std::time::Duration::from_secs(8),
        )
        .ok()?;
        let pods = parse_pods(&text);
        (!pods.is_empty()).then_some(pods)
    })();
    let _ = CACHE.set(out.clone());
    out
}

/// Extract (namespace/name, container ids) from a `kubectl get pods -A -o
/// json` document. Tolerates missing status/containerStatuses (pending
/// pods) — such pods simply can't be matched.
pub fn parse_pods(json: &str) -> Vec<Pod> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
    let empty = Vec::new();
    let items = v.get("items").and_then(|x| x.as_array()).unwrap_or(&empty);
    let mut out = Vec::new();
    for item in items {
        let meta = item.get("metadata");
        let ns = meta
            .and_then(|m| m.get("namespace"))
            .and_then(|x| x.as_str())
            .unwrap_or("default");
        let name = meta
            .and_then(|m| m.get("name"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let container_ids = item
            .get("status")
            .and_then(|s| s.get("containerStatuses"))
            .and_then(|x| x.as_array())
            .map(|statuses| {
                statuses
                    .iter()
                    .filter_map(|st| st.get("containerID").and_then(|x| x.as_str()))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        out.push(Pod { key: format!("{ns}/{name}"), container_ids });
    }
    out
}

/// The pod owning `container_id` ("docker ps" short id or a full id), if
/// any. Runtime prefixes ("docker://", "containerd://") are ignored; a
/// 12-char id matches as a prefix of the 64-char kubelet id.
pub fn find_pod(pods: &[Pod], container_id: &str) -> Option<String> {
    let id = container_id.trim().to_lowercase();
    if id.is_empty() {
        return None;
    }
    pods.iter()
        .find(|p| {
            p.container_ids.iter().any(|cid| {
                let raw = cid.rsplit("://").next().unwrap_or(cid).to_lowercase();
                raw == id || raw.starts_with(&id)
            })
        })
        .map(|p| p.key.clone())
}

/// Fill the pod field of each container. Existing values are kept.
pub fn annotate(containers: &mut [Container]) {
    let Some(pods) = pods() else { return };
    annotate_with(&pods, containers);
}

pub fn annotate_with(pods: &[Pod], containers: &mut [Container]) {
    for c in containers.iter_mut() {
        if c.pod.is_none() {
            c.pod = find_pod(pods, &c.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "items": [
        {"metadata": {"name": "web", "namespace": "prod"},
         "status": {"containerStatuses": [
            {"containerID": "docker://aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"}]}},
        {"metadata": {"name": "pending-pod", "namespace": "dev"}, "status": {}},
        {"metadata": {"name": "queue", "namespace": "prod"},
         "status": {"containerStatuses": [
            {"containerID": "containerd://1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"}]}},
        {"metadata": {"name": "no-namespace"}}
      ]}"#;

    #[test]
    fn parse_extracts_ns_name_and_ids() {
        let pods = parse_pods(SAMPLE);
        assert_eq!(pods.len(), 4);
        assert_eq!(pods[0].key, "prod/web");
        assert_eq!(pods[0].container_ids.len(), 1);
        // pending pod: no statuses — empty id list, still listed
        assert!(pods[1].container_ids.is_empty());
        assert_eq!(pods[2].key, "prod/queue");
        // missing namespace falls back to "default"
        assert_eq!(pods[3].key, "default/no-namespace");
    }

    #[test]
    fn parse_garbage_is_empty() {
        assert!(parse_pods("").is_empty());
        assert!(parse_pods("not json").is_empty());
        assert!(parse_pods("{}").is_empty());
    }

    #[test]
    fn find_pod_matches_full_short_and_prefixed() {
        let pods = parse_pods(SAMPLE);
        let full = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999";
        // full id with the runtime prefix stripped on the kubectl side
        assert_eq!(find_pod(&pods, full).as_deref(), Some("prod/web"));
        // docker-ps-style 12-char short id (suffix of the 64-hex id)
        assert_eq!(find_pod(&pods, "aaaabbbbcccc").as_deref(), Some("prod/web"));
        // containerd-prefixed id, uppercase input
        assert_eq!(
            find_pod(&pods, "111122223333").as_deref(),
            Some("prod/queue")
        );
        assert_eq!(find_pod(&pods, "ffff0000"), None);
        assert_eq!(find_pod(&pods, ""), None);
    }

    #[test]
    fn annotate_fills_and_keeps_existing() {
        let pods = parse_pods(SAMPLE);
        let mut cs = vec![
            Container {
                runtime: "docker".into(),
                id: "aaaabbbbcccc".into(),
                name: "k8s_web".into(),
                image: String::new(),
                command: String::new(),
                state: "running".into(),
                status: String::new(),
                ports: String::new(),
                pod: None,
                restarts: None,
            },
            Container {
                runtime: "docker".into(),
                id: "aaaabbbbcccc".into(),
                name: "k8s_other".into(),
                image: String::new(),
                command: String::new(),
                state: "running".into(),
                status: String::new(),
                ports: String::new(),
                pod: Some("manually/set".into()),
                restarts: None,
            },
            Container {
                runtime: "docker".into(),
                id: String::new(),
                name: "plain".into(),
                image: String::new(),
                command: String::new(),
                state: "running".into(),
                status: String::new(),
                ports: String::new(),
                pod: None,
                restarts: None,
            },
        ];
        annotate_with(&pods, &mut cs);
        // matched by short id
        assert_eq!(cs[0].pod.as_deref(), Some("prod/web"));
        // pre-set value kept
        assert_eq!(cs[1].pod.as_deref(), Some("manually/set"));
        // no id — untouched
        assert_eq!(cs[2].pod, None);
    }
}
