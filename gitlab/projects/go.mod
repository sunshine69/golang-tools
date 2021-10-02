module dump-gitlab-project

go 1.17

replace localhost.com/utils => ../../utils

// replace localhost.com/gitlab/utils => ../utils
replace localhost.com/gitlab/model => ../model

require (
	github.com/goji/httpauth v0.0.0-20160601135302-2da839ab0f4d
	github.com/gorilla/mux v1.8.0
	github.com/mattn/go-sqlite3 v1.14.8
	github.com/mileusna/crontab v1.2.0
	github.com/xanzy/go-gitlab v0.50.4
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	localhost.com/gitlab/model v0.0.0-00010101000000-000000000000
	localhost.com/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/golang/protobuf v1.2.0 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/gorilla/sessions v1.2.1 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.8 // indirect
	github.com/hashicorp/logutils v1.0.0 // indirect
	github.com/json-iterator/go v1.1.11 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/richardlehane/mscfb v1.0.3 // indirect
	github.com/richardlehane/msoleps v1.0.1 // indirect
	github.com/sunshine69/sqlstruct v0.0.0-20210630145711-dae28ed37023 // indirect
	github.com/xuri/efp v0.0.0-20210322160811-ab561f5b45e3 // indirect
	github.com/xuri/excelize/v2 v2.4.1 // indirect
	golang.org/x/net v0.0.0-20210903162142-ad29c8ab022f // indirect
	golang.org/x/oauth2 v0.0.0-20181106182150-f42d05182288 // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	google.golang.org/appengine v1.3.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
