module k8s-delete-old-deployment

replace localhost.com/utils => ../utils

go 1.22

toolchain go1.23.2

require (
	github.com/araddon/dateparse v0.0.0-20210429162001-6b43995a97de
	github.com/json-iterator/go v1.1.12
	localhost.com/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/kr/text v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/net v0.31.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
