package model

// NodeConfig Structure of node config
type NodeConfig struct {
	IP                   string `json:"ip"`
	Port                 int    `json:"port"`
	TTL                  uint8  `json:"ttl"`
	LogPath              string `json:"log_path"`
	PeriodTime           int    `json:"period_time"`           // Millisecond
	PingTimeout          int    `json:"ping_timeout"`          // Millisecend
	DisseminationTimeout int    `json:"dissemination_timeout"` // Millisecend
	FailTimeout          int    `json:"fail_timeout"`          // Millisecond
	IntroducerIP         string `json:"introducer_ip"`
}
