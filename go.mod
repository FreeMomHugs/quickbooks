module github.com/FreeMomHugs/quickbooks

go 1.18

replace github.com/FreeMomHugs/quickbooks/qbdatastore => ../quickbooks/qbdatastore

replace github.com/FreeMomHugs/quickbooks/models => ./models

require (
	github.com/FreeMomHugs/myFMHInternal v1.1.6
	github.com/FreeMomHugs/quickbooks/qbdatastore v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.3.0
	google.golang.org/appengine/v2 v2.0.1
)

require (
	cloud.google.com/go v0.100.2 // indirect
	cloud.google.com/go/compute v1.5.0 // indirect
	cloud.google.com/go/iam v0.3.0 // indirect
	cloud.google.com/go/secretmanager v1.4.0 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/googleapis/gax-go/v2 v2.2.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/net v0.0.0-20220325170049-de3da57026de // indirect
	golang.org/x/oauth2 v0.0.0-20220309155454-6242fa91716a // indirect
	golang.org/x/sys v0.0.0-20220328115105-d36c6a25d886 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/api v0.74.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220608133413-ed9918b62aac // indirect
	google.golang.org/grpc v1.47.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)