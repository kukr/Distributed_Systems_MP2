package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
)

type ConfigOfNode struct {
	IPAddr                  string `json:"ipAddr"`
	PortNum                 int    `json:"portNum"`
	TTL                     uint8  `json:"ttl"`
	LogPath                 string `json:"logPath"`
	PeriodTime              int    `json:"periodTime"`          
	PingTimeout             int    `json:"pingTimeout"`          
	DissTimeout             int    `json:"dissTimeout"`          
	FailTimeout             int    `json:"failTimeout"`          
	IPAddrIntroducer        string `json:"ipAddrIntroducer"`
}

type messageType uint8

const (
	messagePing        messageType = 0
	messageAck         messageType = 1
	messageJoin        messageType = 2
	messageMemList     messageType = 3
	messageLeave       messageType = 4
	messageShowMemList messageType = 5
)

var config ConfigOfNode

// buf: 0:s.ID:0_ip-ts_2:1_ip-ts_1:2_ip-ts_234:3_ip-ts_223
func genBufByte(mType messageType, payloads [][]byte) []byte {
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

func genLeaveBufByte() []byte {
	return genBufByte(messageLeave, [][]byte{})
}

func genShowMemListBufByte() []byte {
	return genBufByte(messageShowMemList, [][]byte{})
}

func executeCommand(command string) [][]byte {
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", config.IP, config.Port))
	if err != nil {
		fmt.Println("Not able to resolve the udp address")
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Println("Not to able to dial udp")
	}

	defer conn.Close()

	var buf []byte
	switch command {
	case "list_mem":
		buf = genShowMemListBufByte()
	case "list_self":
		buf = genShowMemListBufByte()
	case "leave":
		buf = genLeaveBufByte()
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
		fmt.Println("Usage: cli_tool [list_mem, list_self, join, leave]")
	} else {
		switch args[1] {
		case "list_mem":
			bufList := executeCommand(args[1])
			if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
				fmt.Println("Membership List:")
				if len(bufList) > 3 {
					for _, buf := range bufList[2:] {
						message := bytes.Split(buf, []byte("_"))
						// message = [[ip-ts], [inc]]
						nodeID := string(message[0])
						inc := int(message[1][0])
						fmt.Printf("list_self: %s, inc: %d\n", nodeID, inc)
					}
				}
			}
		case "list_self":
			bufList := executeCommand(args[1])
			if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
				fmt.Printf("ID: %s\n", bufList[1])
			}

		case "join":
			bufList := executeCommand(args[1])
			if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
				fmt.Println("Join the group")
			}


		case "leave":
			bufList := executeCommand(args[1])
			if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
				fmt.Println("Leave the group")
			}

		default:
			fmt.Println("Usage: cli_tool [list_mem, list_self, join, leave]")
		}
	}
}
