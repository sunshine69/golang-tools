module dump-gitlab-project

go 1.22

toolchain go1.23.2

replace localhost.com/utils => ../../utils

replace localhost.com/gitlab/utils => ../utils

replace localhost.com/gitlab/model => ../model

require (
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/sessions v1.2.1
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/mattn/go-sqlite3 v1.14.11
	github.com/mileusna/crontab v1.2.0
	// Do not upgrade - they change a lot in api call, not a good thing for a SDK like this
	// I tried with current v0.55.1 need to revamp lots of things
	github.com/xanzy/go-gitlab v0.51.1
	github.com/xuri/excelize/v2 v2.5.0
	golang.org/x/crypto v0.29.0
	localhost.com/gitlab/model v0.0.0-00010101000000-000000000000
	localhost.com/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/hashicorp/logutils v1.0.0 // indirect
	localhost.com/gitlab/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/golang/protobuf v1.2.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/richardlehane/mscfb v1.0.3 // indirect
	github.com/richardlehane/msoleps v1.0.1 // indirect
	github.com/sendgrid/rest v2.6.8+incompatible // indirect
	github.com/sendgrid/sendgrid-go v3.11.0+incompatible // indirect
	github.com/sunshine69/golang-tools/utils v0.0.0-20211014012854-151882ff7c1a // indirect
	github.com/sunshine69/sqlstruct v0.0.0-20210630145711-dae28ed37023 // indirect
	github.com/xuri/efp v0.0.0-20210322160811-ab561f5b45e3 // indirect
	golang.org/x/net v0.31.0 // indirect
	golang.org/x/oauth2 v0.0.0-20181106182150-f42d05182288 // indirect
	golang.org/x/text v0.20.0 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	google.golang.org/appengine v1.3.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
