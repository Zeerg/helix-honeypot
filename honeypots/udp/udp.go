package udp

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"helix-honeypot/model"
	"helix-honeypot/logger"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
)

func StartUDPHoneypot(cfg *model.Config) {

	serverInfo := fmt.Sprintf("%s:%s", cfg.UDP.Host, cfg.UDP.Port)
	listen, err := net.ListenPacket("udp", serverInfo)

	if err != nil {
		fmt.Println(err)
		return
	}
	defer listen.Close()

	// Initialize logger
	customLogger, err := logger.NewCustomLogger(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		buf := make([]byte, 1024)
		n, addr, err := listen.ReadFrom(buf)
		if err != nil {
			continue
		}
		go serve(cfg.MachineID, listen, addr, buf[:n], customLogger)
	}
}

func serve(machineID string, listen net.PacketConn, addr net.Addr, buf []byte, customLogger *logger.LocalCustomLogger) {

	remoteHost, remotePort, err := net.SplitHostPort(addr.String())
	if err != nil {
		fmt.Println(err)
		return
	}

	var message model.UDPMessage
	messageID := uuid.New()
	message.MessageId = messageID.String()
	message.Timestamp = time.Now().UTC().Unix()
	message.RemoteIP = remoteHost
	message.RemotePort = remotePort
	message.Data = string(buf)

	data, err := json.Marshal(message)
	if err != nil {
		fmt.Println("error:", err)
	}

	// Unmarshal JSON string to bson.M
	var messageObject bson.M
	err = json.Unmarshal(data, &messageObject)
	if err != nil {
		fmt.Println("error:", err)
	}

	// Log the incoming request
	entryFields := logrus.Fields{
		"message": messageObject,
	}

	customLogger.Logger.WithFields(entryFields).Info("Received UDP request")

	// Log to MongoDB
	if customLogger.Cfg.MongoDB.LogToMongoDB {
		customLogger.LogToMongoDB(entryFields, time.Now())
	}
}
