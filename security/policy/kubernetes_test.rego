package main

import rego.v1

test_privileged_rejected if {
    some message in deny with input as {"kind": "Pod", "spec": {"containers": [{"name": "unsafe", "securityContext": {"privileged": true}}]}}
    startswith(message, "K8S005:")
}

test_non_workload_ignored if {
    count(deny) == 0 with input as {"kind": "ConfigMap", "data": {"key": "value"}}
}

test_zero_quantity_rejected if {
    not positive_quantity("0Mi")
    not positive_quantity(0)
    positive_quantity("0.5")
    positive_quantity("250m")
}
