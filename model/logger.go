package model

import (

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

// CustomLogger is a custom logger implementation that logs every part of the request.
type CustomLogger struct {
	Logger              *logrus.Logger
	Collection          *mongo.Collection
	EnableMongoDBLogging bool
	Cfg                 *Config
	MachineID           string
	Location     	    string
}
