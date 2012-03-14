all: client server

client: client.go pgptypes.go
	go build -o client client.go pgptypes.go

server: server.go
	go build server.go

clean:
	rm -f client server

