package util

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l LogLevel) String() string {
	return [...]string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}[l]
}

// IncidentData represents all information captured when an incident occurs
type IncidentData struct {
	Timestamp  time.Time
	Level      string
	Message    string
	File       string
	Line       int
	Function   string
	StackTrace string
	Data       string // JSON representation of context data
}

// IncidentReporter defines an interface that must be implemented
// by any struct that wants to receive and store incidents
type IncidentReporter interface {
	ReportIncident(ctx context.Context, data IncidentData) error
}

// IncidentLogger captures incident data and passes it to a reporter
type IncidentLogger struct {
	reporter IncidentReporter
}

// NewIncidentLogger creates a new incident logger with the given reporter
func NewIncidentLogger(reporter IncidentReporter) *IncidentLogger {
	return &IncidentLogger{
		reporter: reporter,
	}
}

// LogIncident logs an incident using the configured reporter
func (l *IncidentLogger) LogIncident(ctx context.Context, level LogLevel, message string, data interface{}) error {
	// Get caller information
	pc, file, line, _ := runtime.Caller(2)
	fn := runtime.FuncForPC(pc)

	// Convert data to JSON
	var dataJSON string
	if data != nil {
		bytes, err := json.Marshal(data)
		if err != nil {
			dataJSON = fmt.Sprintf("Error marshaling data: %v", err)
		} else {
			dataJSON = string(bytes)
		}
	}

	// Get stack trace for errors and fatals
	var stackTrace string
	if level >= ERROR {
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		stackTrace = string(buf[:n])
	}

	// Create incident data
	incidentData := IncidentData{
		Timestamp:  time.Now(),
		Level:      level.String(),
		Message:    message,
		File:       file,
		Line:       line,
		Function:   fn.Name(),
		StackTrace: stackTrace,
		Data:       dataJSON,
	}

	// Use the reporter to store the incident
	return l.reporter.ReportIncident(ctx, incidentData)
}

// Convenience methods
func (l *IncidentLogger) Debug(ctx context.Context, message string, data interface{}) error {
	return l.LogIncident(ctx, DEBUG, message, data)
}

func (l *IncidentLogger) Info(ctx context.Context, message string, data interface{}) error {
	return l.LogIncident(ctx, INFO, message, data)
}

func (l *IncidentLogger) Warn(ctx context.Context, message string, data interface{}) error {
	return l.LogIncident(ctx, WARN, message, data)
}

func (l *IncidentLogger) Error(ctx context.Context, message string, data interface{}) error {
	return l.LogIncident(ctx, ERROR, message, data)
}

func (l *IncidentLogger) Fatal(ctx context.Context, message string, data interface{}) error {
	return l.LogIncident(ctx, FATAL, message, data)
}
