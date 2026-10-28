package main

import rego.v1

public_access_fields := {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

resource_changes contains resource if {
    resource := input.resource_changes[_]
    object.get(resource.change, "after", null) != null
}

deny contains sprintf("TF001: %s must set %s true", [resource.address, field]) if {
    some resource in resource_changes
    resource.type == "aws_s3_bucket_public_access_block"
    some field in public_access_fields
    object.get(resource.change.after, field, false) != true
}

deny contains sprintf("TF002: %s has an unknown public access setting %s", [resource.address, field]) if {
    some resource in resource_changes
    resource.type == "aws_s3_bucket_public_access_block"
    some field in public_access_fields
    object.get(object.get(resource.change, "after_unknown", {}), field, false) == true
}

deny contains sprintf("TF003: %s cannot use a public ACL", [resource.address]) if {
    some resource in resource_changes
    resource.type in {"aws_s3_bucket", "aws_s3_bucket_acl"}
    object.get(resource.change.after, "acl", "private") != "private"
}

deny contains sprintf("TF004: %s requires an explicit public access block in the same plan", [resource.address]) if {
    some resource in resource_changes
    resource.type == "aws_s3_bucket"
    not matching_block(resource)
}

matching_block(bucket) if {
    some block in resource_changes
    block.type == "aws_s3_bucket_public_access_block"
    bucket_name := object.get(bucket.change.after, "bucket", "")
    bucket_name != ""
    block.change.after.bucket == bucket_name
}

deny contains sprintf("TF005: %s must encrypt benchmark results with AES256 or aws:kms", [resource.address]) if {
    some resource in resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    not valid_encryption(resource.change.after)
}

valid_encryption(after) if {
    rule := after.rule[_]
    rule.apply_server_side_encryption_by_default[_].sse_algorithm in {"AES256", "aws:kms"}
}

deny contains sprintf("TF006: %s requires an explicit encryption configuration in the same plan", [resource.address]) if {
    some resource in resource_changes
    resource.type == "aws_s3_bucket"
    not matching_encryption(resource)
}

matching_encryption(bucket) if {
    some encryption in resource_changes
    encryption.type == "aws_s3_bucket_server_side_encryption_configuration"
    bucket_name := object.get(bucket.change.after, "bucket", "")
    bucket_name != ""
    encryption.change.after.bucket == bucket_name
    valid_encryption(encryption.change.after)
}
