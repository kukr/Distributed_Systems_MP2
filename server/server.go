// Package server package for server
package server

// refer to https://varshneyabhi.wordpress.com/2014/12/23/simple-udp-clientserver-in-golang/

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"CS425/CS425-MP2/model"
)

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

type suspiciousMessage struct {
	Type suspiciousStatus
	Inc  uint8
	TS   time.Time
}

type sortMemList []string

func (s sortMemList) Len() int {
	return len(s)
}
func (s sortMemList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s sortMemList) Less(i, j int) bool {
	ipi := strings.Split(s[i], "-")[0]
	ipj := strings.Split(s[j], "-")[0]
	return ipi < ipj
}

func shuffleMemList(memList []string) {
	rand.Seed(time.Now().UnixNano())
	for i := len(memList) - 1; i > 0; i-- { // Fisher–Yates shuffle
		j := rand.Intn(i + 1)
		memList[i], memList[j] = memList[j], memList[i]
	}
}

// Server server class
type Server struct {
	ID                  string
	serverLoopKey       bool
	failureDetectionKey bool
	config              model.NodeConfig
	pingIter            int
	ServerConn          *net.UDPConn
	memList             map[string]uint8 // { "id-ts": 0 }
	sortedMemList       []string         // ["id-ts", ...]
	// { "id-ts": { "type" : 0, "int": 0 } }
	suspiciousCachedMessage      map[string]suspiciousMessage
	suspiciousCachedMessageMutex sync.Mutex
	joinCachedMessage            map[string]time.Time // {"ip-ts_ttl": timestamp}
	joinCachedMessageMutex       sync.Mutex
	leaveCachedMessage           map[string]time.Time // {"ip-ts_ttl": timestamp}
	leaveCachedMessageMutex      sync.Mutex
	suspectList                  map[string]time.Time // {"ip-ts": timestamp}
	pingList                     []string             // ['ip-ts']
	failTimeout                  time.Duration
	cachedTimeout                time.Duration
}

// NewServer init a server
func NewServer(jsonFile []byte) *Server {
	server := &Server{}
	server.loadConfigFromJSON(jsonFile)
	server.init()
	return server
}

// GetConfigPath export config file path
func (s *Server) GetConfigPath() string {
	return s.config.LogPath
}

// GetID export ID
func (s *Server) GetID() string {
	return s.ID
}

func (s *Server) findIndexInSortedMemList(nodeID string) int {
	for k, v := range s.sortedMemList {
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
	return s.suspiciousCachedMessage[nodeID].Inc
}

func (s *Server) loadConfigFromJSON(jsonFile []byte) error {
	return json.Unmarshal(jsonFile, &s.config)
}

func (s *Server) init() {
	s.ID = fmt.Sprintf("%s-%d", s.config.IP, time.Now().Unix())
	s.serverLoopKey = true
	s.failureDetectionKey = true
	s.pingIter = 0
	s.memList = map[string]uint8{s.ID: 0}
	s.generateSortedMemList()
	s.suspiciousCachedMessage = map[string]suspiciousMessage{}
	s.joinCachedMessage = map[string]time.Time{}
	s.leaveCachedMessage = map[string]time.Time{}
	s.suspectList = map[string]time.Time{}
	s.pingList = []string{}
	s.failTimeout = s.calculateTimeoutDuration(s.config.FailTimeout)
	s.cachedTimeout = s.calculateTimeoutDuration(s.config.DisseminationTimeout)
}

// GetIP getip for server
func (s *Server) GetIP() string {
	return s.config.IP
}

// SetIP setip for server
func (s *Server) SetIP(IP string) {
	s.config.IP = IP
}

// GetPort getport of server
func (s *Server) GetPort() int {
	return s.config.Port
}

// GetMemberList return sortedMemList
func (s *Server) GetMemberList() []string {
	return s.sortedMemList
}

// SetPort setport for server
func (s *Server) SetPort(port int) {
	s.config.Port = port
}

// ListenUDP Server listen to udp
func (s *Server) ListenUDP() error {
	/* Lets prepare a address at any address at port s.config.Port*/
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.config.Port))
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

func (s *Server) generateSortedMemList() {
	tmpMemList := []string{}
	for k := range s.memList {
		tmpMemList = append(tmpMemList, k)
	}
	sort.Sort(sortMemList(tmpMemList))
	s.sortedMemList = tmpMemList
}

func (s *Server) generateFullPingList() error {
	tmpPingList := s.sortedMemList
	shuffleMemList(tmpPingList)
	s.pingList = tmpPingList
	s.pingIter = 0

	//log.Printf("generatePingList: i: %d, memList: %v, pingList: %v", i, s.sortedMemList, s.pingList)
	return nil
}

func (s *Server) generatePingList() error {
	i := s.findIndexInSortedMemList(s.ID)
	if i >= 4 {
		s.pingList = []string{}
		s.pingIter = 0
	} else if i == -1 {
		s.pingList = []string{}
		s.pingIter = 0
	} else {
		coreNodeList := []string{}
		coreNodeListSize := 4
		if len(s.sortedMemList) < 4 {
			coreNodeListSize = len(s.sortedMemList)
		}
		for i := 0; i < coreNodeListSize; i++ {
			if s.sortedMemList[i] != s.ID {
				coreNodeList = append(coreNodeList, s.sortedMemList[i])
			}
		}
		//if len(s.sortedMemList) < 4 {
		//coreNodeList = s.sortedMemList
		//} else {
		//coreNodeList = s.sortedMemList[0:4]
		//}
		leafNodeList := []string{}

		for j := 4; j < len(s.sortedMemList); j++ {
			if j%4 == i {
				leafNodeList = append(leafNodeList, s.sortedMemList[j])
			}
		}
		shuffleMemList(coreNodeList)
		shuffleMemList(leafNodeList)
		s.pingList = append(coreNodeList, leafNodeList...)
		s.pingIter = 0
	}
	//log.Printf("generatePingList: i: %d, memList: %v, pingList: %v", i, s.sortedMemList, s.pingList)
	return nil
}

func (s *Server) newNode(nodeID string, inc uint8) {
	if _, ok := s.memList[nodeID]; !ok {
		log.Println("----------------------------- New Node ------------------------------")
		s.memList[nodeID] = inc
		s.generateSortedMemList()
		//s.generateFullPingList()
		s.generatePingList()
		log.Printf("%s_%d join the group", nodeID, inc)
		log.Printf("memList update: %s\n\n", s.sortedMemList)
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
		s.pushSuspiciousCachedMessage(suspiciousFail, nodeID, s.getIncFromCachedMessages(nodeID), s.cachedTimeout)
		delete(s.memList, nodeID)
		s.generateSortedMemList()
		//s.generateFullPingList()
		s.generatePingList()
		log.Printf("memList update: %s\n\n", s.sortedMemList)
	}
}

func (s *Server) suspectNode(nodeID string, failTimeout time.Duration, cachedTimeout time.Duration) {
	if _, ok := s.suspectList[nodeID]; !ok {
		s.suspectList[nodeID] = time.Now().Add(failTimeout)
		go s.failNode(nodeID, failTimeout)
		s.pushSuspiciousCachedMessage(suspiciousSuspect, nodeID, s.memList[nodeID], cachedTimeout)
	}

}

func (s *Server) failNode(nodeID string, timeout time.Duration) {
	time.Sleep(timeout)
	if _, ok := s.suspectList[nodeID]; ok {
		delete(s.suspectList, nodeID)
		s.deleteNode(nodeID)
	}
}

// JoinToGroup join to group
func (s *Server) JoinToGroup() error {
	// introducer don't need to join to group
	if s.config.IP == s.config.IntroducerIP {
		return nil
	}

	joinAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.config.IntroducerIP, s.config.Port))
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
	//log.Printf("JoinToGroup: receive message: %s", buf)

	// buf: messageMemList:s.ID:ip-ts_inc:ip-ts_inc:...
	bufList := bytes.Split(buf, []byte(":"))
	if len(bufList[0]) > 0 && bufList[0][0] == byte(messageMemList) {
		// bufList = [[messageShowMemList], [s.ID], [ip-ts_inc], [ip-ts_inc], ...]
		s.DealWithMemList(bufList[2:])
	}
	return nil
}

func (s *Server) pushSuspiciousCachedMessage(sStatus suspiciousStatus, nodeID string, inc uint8, timeout time.Duration) {
	s.suspiciousCachedMessageMutex.Lock()
	if _, ok := s.memList[nodeID]; !ok {
		return
	}

	susMessage := s.suspiciousCachedMessage[nodeID]
	if susMessage.Type == suspiciousFail {
		return
	}

	newTS := time.Now().Add(timeout) // timeout = s.calculateTimeoutDuration(s.config.XXTimeout)
	if sStatus == suspiciousFail || inc > susMessage.Inc {
		s.suspiciousCachedMessage[nodeID] = suspiciousMessage{Type: sStatus, Inc: inc, TS: newTS}
	} else if inc == susMessage.Inc && susMessage.Type == suspiciousAlive && sStatus == suspiciousSuspect {
		s.suspiciousCachedMessage[nodeID] = suspiciousMessage{Type: sStatus, Inc: inc, TS: newTS}
	}
	s.suspiciousCachedMessageMutex.Unlock()
}

func (s *Server) pushJoinCachedMessage(nodeID string, ttl uint8, timeout time.Duration) {
	s.joinCachedMessageMutex.Lock()
	buf := bytes.NewBufferString(nodeID)
	buf.WriteByte('_')
	buf.WriteByte(byte(ttl))
	if _, ok := s.joinCachedMessage[buf.String()]; !ok {
		s.joinCachedMessage[buf.String()] = time.Now().Add(timeout)
	}
	s.joinCachedMessageMutex.Unlock()
}

func (s *Server) pushLeaveCachedMessage(nodeID string, ttl uint8, timeout time.Duration) {
	s.leaveCachedMessageMutex.Lock()
	buf := bytes.NewBufferString(nodeID)
	buf.WriteByte('_')
	buf.WriteByte(byte(ttl))
	if _, ok := s.leaveCachedMessage[buf.String()]; !ok {
		s.leaveCachedMessage[buf.String()] = time.Now().Add(timeout)
	}
	s.leaveCachedMessageMutex.Unlock()
}

func (s *Server) getCachedMessages() [][]byte {
	// Get cached messages from s.suspiciousCachedMessage, s.joinCachedMessage, s.leaveCachedMessage
	messages := make([][]byte, 0)

	s.joinCachedMessageMutex.Lock()
	for k, v := range s.joinCachedMessage {
		if time.Now().Sub(v) > 0 {
			delete(s.joinCachedMessage, k)
		} else {
			buf := []byte{byte(payloadJoin)}
			buf = append(buf, byte('_'))
			buf = append(buf, []byte(k)...)
			messages = append(messages, buf)
		}
	}
	s.joinCachedMessageMutex.Unlock()

	s.leaveCachedMessageMutex.Lock()
	//log.Printf("getCachedMessages: s.leaveCachedMessage: %v", s.leaveCachedMessage)
	for k, v := range s.leaveCachedMessage {
		if time.Now().Sub(v) > 0 {
			log.Printf("getCachedMessages: delete leave message: %v\n", k)
			delete(s.leaveCachedMessage, k)
		} else {
			buf := []byte{byte(payloadLeave)}
			buf = append(buf, byte('_'))
			buf = append(buf, []byte(k)...)
			messages = append(messages, buf)
		}
	}
	s.leaveCachedMessageMutex.Unlock()

	s.suspiciousCachedMessageMutex.Lock()
	//log.Printf("getCachedMessages: s.suspiciousCachedMessage: %v", s.suspiciousCachedMessage)
	for k, v := range s.suspiciousCachedMessage {
		if time.Now().Sub(v.TS) > 0 {
			delete(s.suspiciousCachedMessage, k)
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
	s.suspiciousCachedMessageMutex.Unlock()

	return messages
}

// Ping ping/ack error detection
func (s *Server) Ping(nodeID string, ch chan bool) {
	pingAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", strings.Split(nodeID, "-")[0], s.config.Port))
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

	payloads := s.getCachedMessages()
	replyBuf := s.generateBuffer(messagePing, payloads)

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
	//log.Printf("Ping: receive message: %s", buf)

	// buf: 0:s.ID:0_ip-ts_2:1_ip-ts_1:2_ip-ts_234:3_ip-ts_223
	// bufList[0]: [messageType]
	// bufList[1]: ip-ts
	// bufList[2:]: payload messages
	bufList := bytes.Split(buf, []byte(":"))
	if bufList[0][0] == byte(messageAck) {
		if len(bufList) > 2 {
			s.DealWithPayloads(bufList[2:])
		}
	}
	ch <- true
}

// DealWithJoin will deal with new joins in our network
// inpMsg: [ip-ts]
func (s *Server) DealWithJoin(inpMsg []byte) {
	nodeID := string(inpMsg)

	s.newNode(nodeID, uint8(0))
	s.pushJoinCachedMessage(nodeID, s.config.TTL, s.cachedTimeout)
}

// DealWithLeave deal with messageLeave
func (s *Server) DealWithLeave(buf []byte) {
	s.pushLeaveCachedMessage(s.ID, s.config.TTL, s.cachedTimeout)
	log.Printf("DealWithLeave: s.leaveCachedMessage: %v\n", s.leaveCachedMessage)
	go func() {
		fmt.Println("-------- Leaving ---------")
		fmt.Println("Server will quit after DisseminationTimeout!")
		time.Sleep(s.cachedTimeout)
		s.failureDetectionKey = false
		s.serverLoopKey = false
		fmt.Println("------- The End -------")
	}()
}

// DealWithPayloads deal with all kinds of messages
// payloads: [[0_ip-ts_2], [1_ip-ts_1], [2_ip-ts_234], [3_ip-ts_223]]
func (s *Server) DealWithPayloads(payloads [][]byte) {
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
				s.pushJoinCachedMessage(nodeID, ttl, s.cachedTimeout)
			}
		case payloadLeave:
			if _, ok := s.memList[nodeID]; ok {
				log.Printf("------------------- Node Leave -------------------")
				log.Printf("%s is leaving....\n\n", nodeID)
			}
			s.deleteNode(nodeID)
			ttl := uint8(message[2][0]) - 1
			if ttl > 0 {
				s.pushLeaveCachedMessage(nodeID, ttl, s.cachedTimeout)
			}
		case payloadSuspicious:
			inc := uint8(message[2][0])
			if nodeID == s.ID {
				if inc >= s.memList[s.ID] {
					s.memList[s.ID] = inc + uint8(1)
					s.pushSuspiciousCachedMessage(suspiciousAlive, nodeID, s.memList[s.ID], s.cachedTimeout)
				}
			} else {
				s.pushSuspiciousCachedMessage(suspiciousSuspect, nodeID, inc, s.cachedTimeout)
			}
		case payloadAlive:
			inc := uint8(message[2][0])
			if _, ok := s.suspectList[nodeID]; ok && s.memList[nodeID] < inc {
				delete(s.suspectList, nodeID)
				s.memList[nodeID] = inc
			}
			s.pushSuspiciousCachedMessage(suspiciousAlive, nodeID, inc, s.cachedTimeout)
		case payloadFail:
			s.deleteNode(nodeID)
		}
	}
}

// DealWithMemList deal with messages contains memList
// bufList = [[ip-ts_inc], [ip-ts_inc], ...]
func (s *Server) DealWithMemList(bufList [][]byte) {
	for _, buf := range bufList {
		message := bytes.Split(buf, []byte("_"))
		// message = [[ip-ts], [inc]]
		nodeID := string(message[0])
		inc := uint8(message[1][0])
		s.newNode(nodeID, inc)
	}
}

// FailureDetection ping loop
func (s *Server) FailureDetection() {
	for s.failureDetectionKey {
		time.Sleep(time.Duration(s.config.PeriodTime) * time.Millisecond)
		if len(s.pingList) == 0 {
			continue
		}
		nodeID := s.pingList[s.pingIter]
		//fmt.Printf("%s: A new ping to %s !\n", time.Now().Format("2006-01-02 15:04:05"), nodeID)
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
			//s.generateFullPingList()
		}
	}
	fmt.Printf("FailureDetection stop!")
}

// buf: 0:s.ID:0_ip-ts_2:1_ip-ts_1:2_ip-ts_234:3_ip-ts_223
func (s *Server) generateBuffer(mType messageType, payloads [][]byte) []byte {
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

// buf: messageJoin:s.ID
func (s *Server) generateJoinBuffer() []byte {
	return s.generateBuffer(messageJoin, [][]byte{})
}

// buf: messageJoin:s.ID
func (s *Server) generateLeaveBuffer() []byte {
	return s.generateBuffer(messageLeave, [][]byte{})
}

// buf: messageMemList:s.ID:ip-ts_inc:ip-ts_inc:ip-ts_inc
func (s *Server) generateMemListBuffer() []byte {
	payloads := [][]byte{}

	for _, nodeID := range s.sortedMemList {
		payload := bytes.NewBufferString(fmt.Sprintf("%s_", nodeID))
		payload.WriteByte(s.memList[nodeID])
		payloads = append(payloads, payload.Bytes())
	}

	return s.generateBuffer(messageMemList, payloads)
}

// ServerLoop main server loop: listen on s.config.port for incoming udp package
func (s *Server) ServerLoop() {
	err := s.ListenUDP()
	if err != nil {
		log.Fatalf("ListenUDP Fail: %v\n", err)
	}
	defer s.ServerConn.Close()

	recBuf := make([]byte, 1024)
	for s.serverLoopKey {
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
		// bufList[0]: [messageType]
		// bufList[1]: ip-ts
		// bufList[2:]: payload messages
		//fmt.Printf("ServerLoop: receive message: messageType: %d, %s\n", bufList[0][0], buf)
		switch messageType(bufList[0][0]) {
		case messageAck:
			if len(bufList) > 2 {
				s.DealWithPayloads(bufList[2:])
			}
		case messagePing:
			if len(bufList) > 2 {
				s.DealWithPayloads(bufList[2:])
			}
			payloads := s.getCachedMessages()
			replyBuf := s.generateBuffer(messageAck, payloads)
			s.ServerConn.WriteTo(replyBuf, addr)
		case messageJoin:
			// buf: messageJoin:ip-ts
			// bufList: [[messageJoin], [ip-ts]]
			s.DealWithJoin(bufList[1])
			replyBuf := s.generateMemListBuffer()
			s.ServerConn.WriteTo(replyBuf, addr)
		case messageMemList:
			// bufList[0]: [messageMemList]
			// bufList[1:]: [[ip-ts], [ip-ts], ...]
			s.DealWithMemList(bufList[1:])
		case messageLeave:
			// buffList: [[messageLeave], [ip-ts]]
			fmt.Println("Leaving the group ...")
			s.DealWithLeave(bufList[1])
			replyBuf := s.generateLeaveBuffer()
			s.ServerConn.WriteTo(replyBuf, addr)
		case messageShowMemList:
			// buffList: [[messageShowMemList], [ip-ts]]
			replyBuf := s.generateMemListBuffer()
			s.ServerConn.WriteTo(replyBuf, addr)
		}
	}
}
