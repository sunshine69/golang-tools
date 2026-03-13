module dump-gitlab-project

go 1.25.0

replace localhost.com/utils => ../../utils

replace localhost.com/gitlab/utils => ../utils

replace localhost.com/gitlab/model => ../model

require (
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/sessions v1.4.0
	github.com/hashicorp/go-retryablehttp v0.7.8
	github.com/mattn/go-sqlite3 v1.14.34
	github.com/mileusna/crontab v1.2.0
	// Do not upgrade - they change a lot in api call, not a good thing for a SDK like this
	// I tried with current v0.55.1 need to revamp lots of things
	github.com/xanzy/go-gitlab v0.115.0
	github.com/xuri/excelize/v2 v2.10.1
	golang.org/x/crypto v0.49.0
	localhost.com/gitlab/model v0.0.0-00010101000000-000000000000
	localhost.com/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/hashicorp/logutils v1.0.0 // indirect
	localhost.com/gitlab/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.18.4 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/richardlehane/mscfb v1.0.6 // indirect
	github.com/richardlehane/msoleps v1.0.6 // indirect
	github.com/sendgrid/rest v2.6.9+incompatible // indirect
	github.com/sendgrid/sendgrid-go v3.16.1+incompatible // indirect
	github.com/sunshine69/golang-tools/utils v0.0.0-20260301065951-e948c2165581 // indirect
	github.com/sunshine69/sqlstruct v0.0.0-20210630145711-dae28ed37023 // indirect
	github.com/tiendc/go-deepcopy v1.7.2 // indirect
	github.com/xuri/efp v0.0.1 // indirect
	github.com/xuri/nfp v0.0.2-0.20250530014748-2ddeb826f9a9 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
