module github.com/FreeMomHugs/qbdatastore

go 1.18

replace github.com/FreeMomHugs/myFMHInternal => ../internal/

replace github.com/FreeMomHugs/quickbooks => ../

require (
	github.com/FreeMomHugs/quickbooks v0.0.0-00010101000000-000000000000
	google.golang.org/appengine/v2 v2.0.1
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)
