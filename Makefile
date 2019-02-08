all: bin.client bin.server

bin.client: client/client.go client/pgptypes.go
	go build -o bin.client ./client

bin.server: server/server.go
	go build -o bin.server ./server

clean:
	rm -f client server

