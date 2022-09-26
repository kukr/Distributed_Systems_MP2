package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
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

type suspiciousStatus uint8

const (
	suspiciousAlive   suspiciousStatus = 0
	suspiciousSuspect suspiciousStatus = 1
	suspiciousFail    suspiciousStatus = 2
)

type payloadType uint8

const (
	payloadJoin       payloadType = 0
	payloadLeave      payloadType = 1
	payloadSuspicious payloadType = 2
	payloadAlive      payloadType = 3
	payloadFail       payloadType = 4
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

type suspiMsg struct {
	Type suspiStat
	Inc  uint8
	TS   time.Time
}

type sortMemList []string

func shuffleMemList(memList []string) {
	rand.Seed(time.Now().UnixNano())
	for i := len(memList) - 1; i > 0; i-- { // Fisher–Yates shuffle
		j := rand.Intn(i + 1)
		memList[i], memList[j] = memList[j], memList[i]
	}
}

type statusKey struct {
	servListKey       bool
	failDetectKey     bool

}

type BufMessageMutex struct {
	suspiCacMsgMutex      sync.Mutex
	joinCacMsgMutex       sync.Mutex
	leaveCacMsgMutex      sync.Mutex
}

type BufMessage struct {
	suspiCacMsg           map[string]suspiMsg
	joinCacMsg            map[string]time.Time
	leaveCacMsg           map[string]time.Time
}

// Server server class
type Server struct {
	ID                  string
	statusKey
	config              ConfigOfNode
	pingIter            int
	ServerConn          *net.UDPConn
	memList             map[string]uint8 // { "id-ts": 0 }
    memListSort         []string         // ["id-ts", ...]
	BufMessage
	BufMessageMutex
	suspectList                  map[string]time.Time // {"ip-ts": timestamp}
	pingList                     []string             // ['ip-ts']
	failTimeout                  time.Duration
	cachedTimeout                time.Duration
}


func (s *Server) findIndInMemListSort(nodeID string) int {
	for k, v := range s.memListSort {
		if v == nodeID {
			return k
		}
	}
	return -1
}

func (s *Server) calculateTimeoutDuration(timeout int) time.Duration {
	return time.Duration(timeout) * time.Millisecond
}

func (s *Server) getIncFromCachedMessages(nodeID string) uint8 {
	return s.BufMessage.suspiCacMsg[nodeID].Inc
}

func (s *Server) loadConf(jsFile []byte) error {
	return json.Unmarshal(jsFile, &s.config)
}

func (s *Server) init() {
	s.ID = fmt.Sprintf("%s-%d", s.config.IPAddr, time.Now().Unix())
	s.statusKey.servListKey = true
	s.statusKey.failDetectKey = true
	s.pingIter = 0
	s.memList = map[string]uint8{s.ID: 0}
	s.genMemListSort()
	s.BufMessage.suspiCacMsg = map[string]suspiMsg{}
	s.BufMessage.joinCacMsg = map[string]time.Time{}
	s.BufMessage.leaveCacMsg = map[string]time.Time{}
	s.suspectList = map[string]time.Time{}
	s.pingList = []string{}
	s.failTimeout = s.calculateTimeoutDuration(s.config.FailTimeout)
	s.cachedTimeout = s.calculateTimeoutDuration(s.config.DissTimeout)
}

// ListenUDP Server listen to udp
func (s *Server) ListenUDP() error {
	/* Lets prepare a address at any address at port s.config.PortNum*/
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.config.PortNum))
	if err != nil {
		return err
	}

	/* Now listen at selected port */
	s.ServerConn, err = net.ListenUDP("udp", serverAddr)
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) genMemListSort() {
	tmpMemList := []string{}
	for k := range s.memList {
		tmpMemList = append(tmpMemList, k)
	}
	sort.Sort(sortMemList(tmpMemList))
	s.memListSort = tmpMemList
}

func (s *Server) generatePingList() error {
	i := s.findIndInMemListSort(s.ID)

	s.pingList = []string{}
	s.pingIter = 0
	noOfMem := len(s.memListSort)

	if i != -1 {
		if len(s.memListSort) < 4 {
			s.pingList = s.memListSort
		} else {
			s.pingList = append(s.pingList, s.memListSort[(i-2)%noOfMem])
			s.pingList = append(s.pingList, s.memListSort[(i-1)%noOfMem])
			s.pingList = append(s.pingList, s.memListSort[(i+1)%noOfMem])
			s.pingList = append(s.pingList, s.memListSort[(i+2)%noOfMem])
		}
	}
	return nil
}

func (s *Server) newNode(nodeID string, inc uint8) {
	if _, ok := s.memList[nodeID]; !ok {
		log.Println("----------------------------- New Node ------------------------------")
		s.memList[nodeID] = inc
		s.genMemListSort()
		s.generatePingList()
		log.Printf("%s_%d join the group", nodeID, inc)
		log.Printf("memList update: %s\n\n", s.memListSort)
	} else {
		if inc > s.memList[nodeID] {
			s.memList[nodeID] = inc
		}
	}
}

func (s *Server) deleteNode(nodeID string) {
	if _, ok := s.memList[nodeID]; ok {
		log.Println("----------------------------- Delete Node ------------------------------")
		log.Printf("%s has been deleted", nodeID)
		s.pushSuspiCacMsg(suspiciousFail, nodeID, s.getIncFromCachedMessages(nodeID), s.cachedTimeout)
		delete(s.memList, nodeID)
		s.genMemListSort()
		s.generatePingList()
		log.Printf("memList update: %s\n\n", s.memListSort)
	}
}

func (s *Server) suspectNode(nodeID string, failTimeout time.Duration, cachedTimeout time.Duration) {
	if _, ok := s.suspectList[nodeID]; !ok {
		s.suspectList[nodeID] = time.Now().Add(failTimeout)
		go s.failNode(nodeID, failTimeout)
		s.pushSuspiCacMsg(suspiciousSuspect, nodeID, s.memList[nodeID], cachedTimeout)
	}

}

func (s *Server) failNode(nodeID string, timeout time.Duration) {
	time.Sleep(timeout)
	if _, ok := s.suspectList[nodeID]; ok {
		delete(s.suspectList, nodeID)
		s.deleteNode(nodeID)
	}
}

// JoinSystems is called in order to join the group of systems
func (s *Server) JoinSystems() error {
	// introducer don't need to join to group
	if s.config.IPAddr == s.config.IPAddrIntroducer {
		return nil
	}

	joinAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.config.IPAddrIntroducer, s.config.PortNum))
	if err != nil {
		return errors.New("unable to resolve udp addr")
	}

	conn, err := net.DialUDP("udp", nil, joinAddr)
	if err != nil {
		return errors.New("unable to dial udp")
	}

	defer conn.Close()

	buf := s.generateJoinBuffer()
	_, err = conn.Write(buf)
	if err != nil {
		return errors.New("unable to write to udp conn")
	}

	recBuf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(recBuf)
	if err != nil {
		return errors.New("unable to read from udp conn")
	}
	buf = recBuf[:n]
	//log.Printf("JoinSystems: receive message: %s", buf)

	// buf: messageMemList:s.ID:ip-ts_inc:ip-ts_inc:...
	bufList := bytes.Split(buf, []byte(":"))
	if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
		// bufList = [[messageShowMemList], [s.ID], [ip-ts_inc], [ip-ts_inc], ...]
		s.ProcessMemList(bufList[2:])
	}
	return nil
}

func (s *Server) pushSuspiCacMsg(sStatus suspiciousStatus, nodeID string, inc uint8, timeout time.Duration) {
	s.BufMessageMutex.suspiCacMsgMutex.Lock()
	if _, ok := s.memList[nodeID]; !ok {
		return
	}

	susMessage := s.BufMessage.suspiCacMsg[nodeID]
	if susMessage.Type == suspiciousFail {
		return
	}

	newTS := time.Now().Add(timeout) // timeout = s.calculateTimeoutDuration(s.config.XXTimeout)
	if sStatus == suspiciousFail || inc > susMessage.Inc {
		s.BufMessage.suspiCacMsg[nodeID] = suspiMsg{Type: sStatus, Inc: inc, TS: newTS}
	} else if inc == susMessage.Inc && susMessage.Type == suspiciousAlive && sStatus == suspiciousSuspect {
		s.BufMessage.suspiCacMsg[nodeID] = suspiMsg{Type: sStatus, Inc: inc, TS: newTS}
	}
	s.BufMessageMutex.suspiCacMsgMutex.Unlock()
}

func (s *Server) pushJoinCacMsg(nodeID string, ttl uint8, timeout time.Duration) {
	s.BufMessageMutex.joinCacMsgMutex.Lock()
	buf := bytes.NewBufferString(nodeID)
	buf.WriteByte('_')
	buf.WriteByte(byte(ttl))
	if _, ok := s.BufMessage.joinCacMsg[buf.String()]; !ok {
		s.BufMessage.joinCacMsg[buf.String()] = time.Now().Add(timeout)
	}
	s.BufMessageMutex.joinCacMsgMutex.Unlock()
}

func (s *Server) pushLeaveCacMsg(nodeID string, ttl uint8, timeout time.Duration) {
	s.BufMessageMutex.leaveCacMsgMutex.Lock()
	buf := bytes.NewBufferString(nodeID)
	buf.WriteByte('_')
	buf.WriteByte(byte(ttl))
	if _, ok := s.BufMessage.leaveCacMsg[buf.String()]; !ok {
		s.BufMessage.leaveCacMsg[buf.String()] = time.Now().Add(timeout)
	}
	s.BufMessageMutex.leaveCacMsgMutex.Unlock()
}

func (s *Server) getCacMsgs() [][]byte {
	// Get cached messages from s.BufMessage.suspiCacMsg, s.BufMessage.joinCacMsg, s.BufMessage.leaveCacMsg
	messages := make([][]byte, 0)

	s.BufMessageMutex.joinCacMsgMutex.Lock()
	for k, v := range s.BufMessage.joinCacMsg {
		if time.Now().Sub(v) > 0 {
			delete(s.BufMessage.joinCacMsg, k)
		} else {
			buf := []byte{byte(payloadJoin)}
			buf = append(buf, byte('_'))
			buf = append(buf, []byte(k)...)
			messages = append(messages, buf)
		}
	}
	s.BufMessageMutex.joinCacMsgMutex.Unlock()

	s.BufMessageMutex.leaveCacMsgMutex.Lock()
	for k, v := range s.BufMessage.leaveCacMsg {
		if time.Now().Sub(v) > 0 {
			log.Printf("getCacMsgs: delete leave message: %v\n", k)
			delete(s.BufMessage.leaveCacMsg, k)
		} else {
			buf := []byte{byte(payloadLeave)}
			buf = append(buf, byte('_'))
			buf = append(buf, []byte(k)...)
			messages = append(messages, buf)
		}
	}
	s.BufMessageMutex.leaveCacMsgMutex.Unlock()

	s.BufMessageMutex.suspiCacMsgMutex.Lock()

	for k, v := range s.BufMessage.suspiCacMsg {
		if time.Now().Sub(v.TS) > 0 {
			delete(s.BufMessage.suspiCacMsg, k)
		} else {
			buf := []byte{}
			switch v.Type {
			case suspiciousAlive:
				buf = append(buf, byte(payloadAlive))
			case suspiciousSuspect:
				buf = append(buf, byte(payloadSuspicious))
			case suspiciousFail:
				buf = append(buf, byte(payloadFail))
			}
			buf = append(buf, byte('_'))
			buf = append(buf, []byte(k)...)
			buf = append(buf, byte('_'))
			buf = append(buf, byte(v.Inc))
			messages = append(messages, buf)
		}
	}
	s.BufMessageMutex.suspiCacMsgMutex.Unlock()

	return messages
}

// Function for processing Pings
func (s *Server) Ping(nodeID string, ch chan bool) {
	pingAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", strings.Split(nodeID, "-")[0], s.config.PortNum))
	if err != nil {
		ch <- false
		return
	}

	conn, err := net.DialUDP("udp", nil, pingAddr)
	if err != nil {
		ch <- false
		return
	}

	defer conn.Close()

	payloads := s.getCacMsgs()
	replyBuf := s.genBufByte(messagePing, payloads)

	_, err = conn.Write(replyBuf)
	if err != nil {
		ch <- false
		return
	}

	recBuf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(recBuf)
	if err != nil || n == 0 {
		ch <- false
		return
	}
	buf := recBuf[:n]

	bufList := bytes.Split(buf, []byte(":"))
	if bufList[0][0] == byte(messageAck) {
		if len(bufList) > 2 {
			s.ProcessPayloads(bufList[2:])
		}
	}
	ch <- true
}

// ProcessJoin will help with adding new nodes to the system
func (s *Server) ProcessJoin(inpMsg []byte) {
	nodeID := string(inpMsg)

	s.newNode(nodeID, uint8(0))
	s.pushJoinCacMsg(nodeID, s.config.TTL, s.cachedTimeout)
}

// ProcessLeave deal with messageLeave
func (s *Server) ProcessLeave(buf []byte) {
	s.pushLeaveCacMsg(s.ID, s.config.TTL, s.cachedTimeout)
	log.Printf("ProcessLeave: s.BufMessage.leaveCacMsg: %v\n", s.BufMessage.leaveCacMsg)
	go func() {
		fmt.Println("Leaving ---------")
		fmt.Println("Server will complete the leave after DissTimeout!")
		time.Sleep(s.cachedTimeout)
		s.statusKey.failDetectKey = false
		s.statusKey.servListKey = false
		fmt.Println("----------")
	}()
}

// ProcessPayloads will process all kinds of messages such as ping, Ack, leave, join etc
func (s *Server) ProcessPayloads(payloads [][]byte) {
	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		message := bytes.Split(payload, []byte("_"))
		// message = [[0], []byte("ip-ts"), [2]]
		nodeID := string(message[1])
		switch payloadType(message[0][0]) {
		case payloadJoin:
			s.newNode(nodeID, uint8(0))
			ttl := uint8(message[2][0]) - 1
			if ttl > 0 {
				s.pushJoinCacMsg(nodeID, ttl, s.cachedTimeout)
			}
		case payloadLeave:
			if _, ok := s.memList[nodeID]; ok {
				log.Printf("Leave -------------------")
				log.Printf("%s is leaving....\n\n", nodeID)
			}
			s.deleteNode(nodeID)
			ttl := uint8(message[2][0]) - 1
			if ttl > 0 {
				s.pushLeaveCacMsg(nodeID, ttl, s.cachedTimeout)
			}
		case payloadSuspicious:
			inc := uint8(message[2][0])
			if nodeID == s.ID {
				if inc >= s.memList[s.ID] {
					s.memList[s.ID] = inc + uint8(1)
					s.pushSuspiCacMsg(suspiciousAlive, nodeID, s.memList[s.ID], s.cachedTimeout)
				}
			} else {
				s.pushSuspiCacMsg(suspiciousSuspect, nodeID, inc, s.cachedTimeout)
			}
		case payloadAlive:
			inc := uint8(message[2][0])
			if _, ok := s.suspectList[nodeID]; ok && s.memList[nodeID] < inc {
				delete(s.suspectList, nodeID)
				s.memList[nodeID] = inc
			}
			s.pushSuspiCacMsg(suspiciousAlive, nodeID, inc, s.cachedTimeout)
		case payloadFail:
			s.deleteNode(nodeID)
		}
	}
}

// ProcessMemList process messages that contains memList
func (s *Server) ProcessMemList(bufList [][]byte) {
	for _, buf := range bufList {
		message := bytes.Split(buf, []byte("_"))
		// message = [[ip-ts], [inc]]
		nodeID := string(message[0])
		inc := uint8(message[1][0])
		s.newNode(nodeID, inc)
	}
}

// Run a loop for so that the node has a process for Failure Detection
func (s *Server) DetectFailure() {
	for s.statusKey.failDetectKey {
		time.Sleep(time.Duration(s.config.PeriodTime) * time.Millisecond)
		if len(s.pingList) == 0 {
			continue
		}
		nodeID := s.pingList[s.pingIter]
		
		ch := make(chan bool)
		go s.Ping(nodeID, ch)

		select {
		case res := <-ch:
			if !res {
				s.suspectNode(nodeID, s.failTimeout, s.cachedTimeout)
			}
		case <-time.After(time.Duration(s.config.PingTimeout) * time.Millisecond):
			s.suspectNode(nodeID, s.failTimeout, s.cachedTimeout)
		}
		//fmt.Printf("Finish ping for %s!\n", nodeID)
		s.pingIter++
		if len(s.pingList) > 0 {
			s.pingIter = s.pingIter % len(s.pingList)
		}

		if s.pingIter == 0 {
			s.generatePingList()
		}
	}
	fmt.Printf("Stop Failure Detection!")
}

func (s *Server) genBufByte(mType messageType, payloads [][]byte) []byte {
	replyBuf := []byte{byte(mType)}              // messageType
	replyBuf = append(replyBuf, ':')             // messageType:
	replyBuf = append(replyBuf, []byte(s.ID)...) // messageType:ip-ts
	for _, payload := range payloads {
		//payload: 0_ip-ts_342
		replyBuf = append(replyBuf, ':')
		replyBuf = append(replyBuf, payload...)
	}
	return replyBuf
}

func (s *Server) genJoinBufByte() []byte {
	return s.genBufByte(messageJoin, [][]byte{})
}

func (s *Server) genLeaveBufByte() []byte {
	return s.genBufByte(messageLeave, [][]byte{})
}

func (s *Server) genByteMemList() []byte {
	payloads := [][]byte{}

	for _, nodeID := range s.memListSort {
		payload := bytes.NewBufferString(fmt.Sprintf("%s_", nodeID))
		payload.WriteByte(s.memList[nodeID])
		payloads = append(payloads, payload.Bytes())
	}

	return s.genBufByte(messageMemList, payloads)
}

// In the LoopforServer check for the key. If true listen on to the port
func (s *Server) LoopforServer() {
	err := s.ListenUDP()
	if err != nil {
		log.Fatalf("ListenUDP Fail: %v\n", err)
	}
	defer s.ServerConn.Close()

	recBuf := make([]byte, 1024)
	for s.statusKey.servListKey {
		n, addr, err := s.ServerConn.ReadFromUDP(recBuf)
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}
		buf := recBuf[:n]

		if len(buf) == 0 {
			continue
		}
		bufList := bytes.Split(buf, []byte(":"))
		
		switch messageType(bufList[0][0]) {
		case messageAck:
			if len(bufList) > 2 {
				s.ProcessPayloads(bufList[2:])
			}
		case messagePing:
			if len(bufList) > 2 {
				s.ProcessPayloads(bufList[2:])
			}
			payloads := s.getCacMsgs()
			replyBuf := s.genBufByte(messageAck, payloads)
			s.ServerConn.WriteTo(replyBuf, addr)
		case messageJoin:
			// buf: messageJoin:ip-ts
			// bufList: [[messageJoin], [ip-ts]]
			s.ProcessJoin(bufList[1])
			replyBuf := s.genByteMemList()
			s.ServerConn.WriteTo(replyBuf, addr)
		case messageMemList:
			// bufList[0]: [messageMemList]
			// bufList[1:]: [[ip-ts], [ip-ts], ...]
			s.ProcessMemList(bufList[1:])
		case messageLeave:
			// buffList: [[messageLeave], [ip-ts]]
			fmt.Println("Leaving the group ...")
			s.ProcessLeave(bufList[1])
			replyBuf := s.generateLeaveBuffer()
			s.ServerConn.WriteTo(replyBuf, addr)
		case messageShowMemList:
			// buffList: [[messageShowMemList], [ip-ts]]
			replyBuf := s.genByteMemList()
			s.ServerConn.WriteTo(replyBuf, addr)
		}
	}
}

// The main function initializes the server and starts it
func main() {
	// parse argument
	confPath := flag.String("c", "./config.json", "Config file path")

	// load config file
	confFil, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatalf("File error: %v\n", err)
	}

	// Initialize an object of server
	s := &Server{}
	s.loadConfigFromJSON(confFil)
	s.init()

	f, err := os.OpenFile(s.config.LogPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("not able to open the file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)

	for {
		err = s.JoinSystems()
		if err != nil {
			log.Printf("Failed to join the systems: %s\n", err.Error())
			log.Printf("try to join the group of systems again after some time")
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("join to group successfully\n\n")
		break
	}

	log.Printf("Server started on IPAddr: %s and port: %d\n\n", s.config.IPAddr, s.config.PortNum)
	go s.LoopforServer()
	s.DetectFailure()
}
