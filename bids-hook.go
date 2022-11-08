package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	server := &http.Server{
		Addr:           "127.0.0.1:2845",
		Handler:        http.HandlerFunc(handle),
		ReadTimeout:    1 * time.Second,
		MaxHeaderBytes: 4 << 10,
	}
	log.Fatal(server.ListenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request) {
	log.Println("handle: got request")
}
