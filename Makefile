deps:
	dep version || (curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh)
	dep ensure -v

test: deps
	go test -v -race ./...

build_linux: deps
	env GOOS=linux CGO_ENABLED=0 go build -o ts2fa -a -installsuffix cgo \
		github.com/tsocial/ts2fa/cli

build_mac: deps
	env GOOS=darwin CGO_ENABLED=0 go build -o ts2fa -a -installsuffix cgo \
		github.com/tsocial/ts2fa/cli
