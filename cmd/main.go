package main

import (
	"fmt"
	"os"

	"helix-honeypot/server"
)

func main() {
	// Start the server based on the run mode
	err := server.StartHoneypot()
	if err != nil {
		fmt.Println("Failed To Start Server:", err)
		os.Exit(1)
	}
}
