package tcp

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

func StartTCPHoneypot(cfg *model.Config) {

	serverInfo := fmt.Sprintf("%s:%s", cfg.TCP.Host, cfg.TCP.Port)
	listen, err := net.Listen("tcp", serverInfo)

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
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go handleConn(cfg.MachineID, conn, customLogger)
	}
}

func handleConn(machineID string, conn net.Conn, customLogger *logger.LocalCustomLogger) {
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Split the remote address into host and port
	remoteHost, remotePort, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		fmt.Println(err)
		return
	}
	
	var message model.TCPMessage
	messageID := uuid.New()
	message.MessageId = messageID.String()
	message.Timestamp = time.Now().UTC().Unix()
	message.RemoteIP = remoteHost
	message.RemotePort = remotePort
	message.Data = string(buf[:n])

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

	customLogger.Logger.WithFields(entryFields).Info("Received TCP request")

	// Log to MongoDB
	if customLogger.Cfg.MongoDB.LogToMongoDB {
		customLogger.LogToMongoDB(entryFields, time.Now())
	}
}
