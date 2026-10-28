package main

import rego.v1

supported_kinds := {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

valid_pod_spec if {
    is_object(pod_spec)
}

deny contains "K8S000: supported workload is missing a pod specification" if {
    input.kind in supported_kinds
    not valid_pod_spec
}

deny contains "K8S016: split Kubernetes List objects into individual resources before policy evaluation" if {
    input.kind == "List"
}

pod_spec := input.spec if input.kind == "Pod"
pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

containers contains container if {
    spec := pod_spec
    field := ["containers", "initContainers", "ephemeralContainers"][_]
    container := object.get(spec, field, [])[_]
}

effective_context(container) := object.union(
    object.get(pod_spec, "securityContext", {}),
    object.get(container, "securityContext", {}),
)

positive_quantity(value) if {
    is_string(value)
    regex.match(`^[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+|[numkKMGTEP]i?)?$`, value)
    regex.match(`[1-9]`, split(regex.replace(value, `[a-zA-Z].*$`, ""), "e")[0])
}
positive_quantity(value) if {
    is_number(value)
    value > 0
}

valid_resource(container, group, name) if {
    positive_quantity(container.resources[group][name])
}

deny contains "K8S001: add at least one application container" if {
    spec := pod_spec
    count(object.get(spec, "containers", [])) == 0
}

deny contains sprintf("K8S002: %s must run as non-root with a nonzero UID", [container.name]) if {
    some container in containers
    context := effective_context(container)
    not object.get(context, "runAsNonRoot", false)
}

deny contains sprintf("K8S003: %s cannot set runAsUser to zero", [container.name]) if {
    some container in containers
    object.get(effective_context(container), "runAsUser", -1) == 0
}

deny contains sprintf("K8S004: %s must set allowPrivilegeEscalation false", [container.name]) if {
    some container in containers
    object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true) != false
}

deny contains sprintf("K8S005: %s cannot be privileged", [container.name]) if {
    some container in containers
    object.get(object.get(container, "securityContext", {}), "privileged", false) != false
}

deny contains sprintf("K8S006: %s must use a read-only root filesystem", [container.name]) if {
    some container in containers
    object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false) != true
}

deny contains sprintf("K8S007: %s must drop ALL capabilities and add none", [container.name]) if {
    some container in containers
    caps := object.get(object.get(container, "securityContext", {}), "capabilities", {})
    not "ALL" in object.get(caps, "drop", [])
}

deny contains sprintf("K8S008: %s cannot add capabilities", [container.name]) if {
    some container in containers
    caps := object.get(object.get(container, "securityContext", {}), "capabilities", {})
    count(object.get(caps, "add", [])) > 0
}

deny contains sprintf("K8S009: %s must use RuntimeDefault seccomp", [container.name]) if {
    some container in containers
    profile := object.get(effective_context(container), "seccompProfile", {})
    object.get(profile, "type", "") != "RuntimeDefault"
}

deny contains sprintf("K8S010: %s needs positive %s.%s", [container.name, group, name]) if {
    some container in containers
    group := ["requests", "limits"][_]
    name := ["cpu", "memory"][_]
    not valid_resource(container, group, name)
}

deny contains sprintf("K8S011: disable %s", [field]) if {
    spec := pod_spec
    field := ["hostNetwork", "hostPID", "hostIPC"][_]
    object.get(spec, field, false) != false
}

deny contains "K8S012: explicitly disable service account token mounting" if {
    spec := pod_spec
    object.get(spec, "automountServiceAccountToken", true) != false
}

deny contains "K8S013: hostPath volumes are forbidden" if {
    spec := pod_spec
    volume := object.get(spec, "volumes", [])[_]
    object.get(volume, "hostPath", null) != null
}

deny contains sprintf("K8S014: %s needs an explicit image tag or SHA256 digest", [container.name]) if {
    some container in containers
    not regex.match(`(@sha256:[a-f0-9]{64}$|:[^/:@]+$)`, container.image)
}

deny contains sprintf("K8S015: %s cannot use the latest image tag", [container.name]) if {
    some container in containers
    endswith(container.image, ":latest")
}
