package main

import rego.v1

test_public_acl_rejected if {
    some message in deny with input as {"resource_changes": [{"address": "aws_s3_bucket.bad", "type": "aws_s3_bucket", "change": {"after": {"bucket": "example", "acl": "public-read"}}}]}
    startswith(message, "TF003:")
}

test_delete_ignored if {
    count(deny) == 0 with input as {"resource_changes": [{"address": "aws_s3_bucket.old", "type": "aws_s3_bucket", "change": {"after": null}}]}
}
