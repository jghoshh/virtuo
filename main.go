package main

import (
	"github.com/jghoshh/virtuo/backend"
	"github.com/jghoshh/virtuo/frontend"
)

func main() {
	backend.RunBackend()
	frontend.RunFrontend()
}
