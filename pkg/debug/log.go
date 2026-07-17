package debug

import (
	"fmt"
	"log"
	"os"
)

var logger *log.Logger
var logFile *os.File

// Init opens path for append-write and installs the logger.
func Init(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	logFile = f
	logger = log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	return nil
}

// Log writes a timestamped line to the debug log if Init was called.
func Log(format string, args ...any) {
	if logger == nil {
		return
	}
	logger.Output(2, fmt.Sprintf(format, args...))
}

// Close flushes and closes the underlying log file.
func Close() {
	if logFile != nil {
		logFile.Close()
		logFile = nil
		logger = nil
	}
}
