package model

type TCPMessage struct {
	DeviceId   string `json:"deviceId"`
	MessageId  string `json:"messageId"`
	Timestamp  int64  `json:"timestamp"`
	RemoteIP   string `json:"remote-ip"`
	RemotePort string `json:"remote_port"`
	Location   string `json:"location"`
	Data       string `json:"data"`
}