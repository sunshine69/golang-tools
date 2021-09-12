module k8s-delete-old-deployment

replace localhost.com/utils => ../utils

go 1.16

require (
	github.com/araddon/dateparse v0.0.0-20210429162001-6b43995a97de
	github.com/json-iterator/go v1.1.11
	localhost.com/utils v0.0.0-00010101000000-000000000000
)
