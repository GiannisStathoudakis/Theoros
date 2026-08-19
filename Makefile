MODULE_NAME := github.com/GiannisStathoudakis/Theoros

.PHONY: install generate clean

install:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest

generate:
	protoc --go_out=. \
		--go_opt=module=$(MODULE_NAME) \
		--connect-go_out=. \
		--connect-go_opt=module=$(MODULE_NAME) \
		proto/theoros/v1/api.proto

clean:
	rm -rf gen/