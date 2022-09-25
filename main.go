package main

import (
	"CS425/CS425-MP2/server"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"
)

// This function will register and initiate server
func main() {
	// parse argument
	configFilePath := flag.String("c", "./config.json", "Config file path")

	// load config file
	configFile, err := ioutil.ReadFile(*configFilePath)
	if err != nil {
		log.Fatalf("File error: %v\n", err)
	}

	// Class for server
	s := server.NewServer(configFile)

	f, err := os.OpenFile(s.GetConfigPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)

	for {
		err = s.JoinToGroup()
		if err != nil {
			log.Printf("join to group failed: %s\n", err.Error())
			log.Printf("try to join to group 5 seconds later...")
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("join to group successfully\n\n")
		break
	}

	log.Printf("Starting server on IP: %s and port: %d\n\n", s.GetIP(), s.GetPort())
	go s.ServerLoop()
	s.FailureDetection()
}
