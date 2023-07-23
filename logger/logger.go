package logger

import (
	"context"
	"io"
	"time"
	"bytes"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson"

	"helix-honeypot/model"
)

type CustomLogger = model.CustomLogger

type LocalCustomLogger struct {
    *CustomLogger // Embed the CustomLogger type. It brings in all fields from the embedded type.
}

// NewCustomLogger creates a new instance of CustomLogger.
func NewCustomLogger(cfg *model.Config) (*LocalCustomLogger, error) {
	logger := logrus.New()

	if cfg.MongoDB.LogToMongoDB {
		// Connect to MongoDB
		clientOptions := options.Client().ApplyURI(cfg.MongoDB.URI)
		client, err := mongo.Connect(context.Background(), clientOptions)
		if err != nil {
			return nil, err
		}

		// Get the MongoDB collection
		collection := client.Database(cfg.MongoDB.Database).Collection(cfg.MongoDB.Collection)

		return &LocalCustomLogger{
			CustomLogger: &CustomLogger{
				Logger:              logger,
				Collection:          collection,
				EnableMongoDBLogging: true,
				Cfg:                 cfg,
				MachineID:           cfg.MachineID,
				Location:			 cfg.RunMode.Location,
			},
		}, nil
		
	}

	return &LocalCustomLogger{
		CustomLogger: &CustomLogger{
			Logger:              logger,
			EnableMongoDBLogging: false,
			Cfg:                 cfg,
			MachineID:           cfg.MachineID,
			Location:			 cfg.RunMode.Location,
		},
	}, nil
}

// Middleware implements the Echo MiddlewareFunc interface.
func (cl *LocalCustomLogger) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		res := c.Response()

		httpLog := &model.HTTPLog{
			Method:    req.Method,
			Path:      req.URL.Path,
			Query:     req.URL.RawQuery,
			Status:    res.Status,
			Response:  res.Size,
			UserAgent: req.UserAgent(),
			RemoteIP:  c.RealIP(),
			Headers:   req.Header,
			MachineID: cl.MachineID[:],
			Location: cl.Location,
		}
		
		entryFields := httpLog.ToLogrusFields()

		// Read the request body
		body, err := io.ReadAll(req.Body)
		if err != nil {
			c.Error(err)
			entryFields["error"] = err
		} else {
			req.Body = io.NopCloser(bytes.NewBuffer(body))
			entryFields["request-body"] = string(body)
		}

		startTime := time.Now()

		if err := next(c); err != nil {
			c.Error(err)
			entryFields["error"] = err
			cl.Logger.WithFields(entryFields).Error("Failed to process request")

			// Log to MongoDB
			if cl.Cfg.MongoDB.LogToMongoDB {
				cl.LogToMongoDB(entryFields, startTime)
			}
		} else {
			cl.Logger.WithFields(entryFields).Info("Request processed successfully")

			// Log to MongoDB
			if cl.Cfg.MongoDB.LogToMongoDB {
				cl.LogToMongoDB(entryFields, startTime)
			}
		}

		return nil
	}
}

func (cl *LocalCustomLogger) LogToMongoDB(entryFields logrus.Fields, startTime time.Time) {
	duration := time.Since(startTime)

	// Create a document from the log entry
	doc := bson.M{
		"level":     entryFields["level"],
		"message":   entryFields["message"],
		"time":      time.Now(),
		"fields":    entryFields,
		"duration":  duration.String(),
		"machine-id": cl.MachineID[:],
		"remote-ip": entryFields["remote-ip"],
		"location": cl.Location,
	}

	// Insert the document into MongoDB
	_, err := cl.Collection.InsertOne(context.Background(), doc)
	if err != nil {
		// Handle the error if necessary
		cl.Logger.WithError(err).Error("Failed to log to MongoDB")
	}
}
