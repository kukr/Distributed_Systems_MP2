package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"CS425/CS425-MP2/model"
)

type messageType uint8

const (
	messagePing        messageType = 0
	messageAck         messageType = 1
	messageJoin        messageType = 2
	messageMemList     messageType = 3
	messageLeave       messageType = 4
	messageShowMemList messageType = 5
)

var config model.NodeConfig

// buf: 0:s.ID:0_ip-ts_2:1_ip-ts_1:2_ip-ts_234:3_ip-ts_223
func generateBuffer(mType messageType, payloads [][]byte) []byte {
	replyBuf := []byte{byte(mType)}                       // messageType
	replyBuf = append(replyBuf, ':')                      // messageType:
	replyBuf = append(replyBuf, []byte("127.0.0.1-0")...) // messageType:ip-ts
	for _, payload := range payloads {
		//payload: 0_ip-ts_342
		replyBuf = append(replyBuf, ':')
		replyBuf = append(replyBuf, payload...)
	}
	return replyBuf
}

func generateLeaveBuffer() []byte {
	return generateBuffer(messageLeave, [][]byte{})
}

func generateShowMemListBuffer() []byte {
	return generateBuffer(messageShowMemList, [][]byte{})
}

func executeCommand(command string) [][]byte {
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", config.IP, config.Port))
	if err != nil {
		fmt.Println("unable to resolve udp addr")
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Println("unable to dial udp")
	}

	defer conn.Close()

	var buf []byte
	switch command {
	case "memberList":
		buf = generateShowMemListBuffer()
	case "nodeID":
		buf = generateShowMemListBuffer()
	case "leave":
		buf = generateLeaveBuffer()
	}

	//fmt.Printf("Send: %s\n", buf)
	_, err = conn.Write(buf)
	if err != nil {
		fmt.Println("unable to write to udp conn")
	}

	recBuf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(recBuf)
	if err != nil {
		fmt.Println("unable to read from udp conn")
	}
	buf = recBuf[:n]

	// buf: messageMemList:s.ID:ip-ts_inc:ip-ts_inc:...
	return bytes.Split(buf, []byte(":"))
}

func main() {
	// load config file
	configFile, err := ioutil.ReadFile("./config.json")
	if err != nil {
		fmt.Printf("File error: %v\n", err)
	}

	json.Unmarshal(configFile, &config)
	args := os.Args
	if len(args) < 2 || len(args) > 2 {
		fmt.Println("Usage: cli_tool [memberList, nodeID, leave]")
	} else {
		switch args[1] {
		case "memberList":
			bufList := executeCommand(args[1])
			// buf: messageMemList:s.ID:ip-ts_inc:ip-ts_inc:ip-ts_inc
			if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
				// bufList = [[messageShowMemList], [s.ID], [ip-ts_inc], [ip-ts_inc], ...]
				fmt.Println("Membership List:")
				if len(bufList) > 3 {
					for _, buf := range bufList[2:] {
						message := bytes.Split(buf, []byte("_"))
						// message = [[ip-ts], [inc]]
						nodeID := string(message[0])
						inc := int(message[1][0])
						fmt.Printf("nodeID: %s, inc: %d\n", nodeID, inc)
					}
				}
			}
		case "nodeID":
			bufList := executeCommand(args[1])
			// buf: messageMemList:s.ID:ip-ts_inc:ip-ts_inc:ip-ts_inc
			if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
				// bufList = [[messageShowMemList], [s.ID], [ip-ts_inc], [ip-ts_inc], ...]
				fmt.Printf("ID: %s\n", bufList[1])
			}
		case "leave":
			bufList := executeCommand(args[1])
			if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
				// bufList = [[messageLeave], [s.ID]]
				fmt.Println("Leave the group")
			}
		default:
			fmt.Println("Usage: cli_tool [memberList, nodeID, leave]")
		}
	}
}
