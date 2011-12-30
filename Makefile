all: client server

client: client.go pgptypes.go
	6g -o client.6 client.go pgptypes.go
	6l -o client client.6

server: server.go
	6g server.go
	6l -o server server.6
