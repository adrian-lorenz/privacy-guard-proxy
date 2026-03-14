package proxy

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const maxLogBytes = 10 * 1024 * 1024 // 10 MB

// Logger writes one-line request entries to a per-proxy log file.
// When the file reaches 10 MB it is renamed to .log.old and a new file is started.
// Only metadata is logged — no request/response content, no PII values.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	path string
	size int64
}

// LogEntry holds the metadata to be recorded for a single request.
type LogEntry struct {
	Method     string
	Path       string // path only, no query string
	StatusCode int
	RespBytes  int
	PIICount   int
	PIITypes   []string // unique PII types found (e.g. ["EMAIL","IBAN"])
}

// NewLogger opens (or creates) the log file for the given proxy port.
func NewLogger(port int) *Logger {
	os.MkdirAll("logs", 0755)
	path := fmt.Sprintf("logs/proxy_%d.log", port)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return &Logger{path: path}
	}
	info, _ := f.Stat()
	return &Logger{file: f, path: path, size: info.Size()}
}

// Write appends one log line. Safe for concurrent use.
func (l *Logger) Write(e LogEntry) {
	if l == nil || l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size >= maxLogBytes {
		l.rotate()
	}
	piiSuffix := fmt.Sprintf("pii=%d", e.PIICount)
	if len(e.PIITypes) > 0 {
		piiSuffix += " [" + strings.Join(e.PIITypes, ",") + "]"
	}
	line := fmt.Sprintf("%s  %-6s %-30s  %d  %5d B  %s\n",
		time.Now().UTC().Format("2006-01-02 15:04:05"),
		e.Method, e.Path, e.StatusCode, e.RespBytes, piiSuffix)
	n, _ := l.file.WriteString(line)
	l.size += int64(n)
}

func (l *Logger) rotate() {
	l.file.Close()
	os.Rename(l.path, l.path+".old")
	f, _ := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY, 0644)
	l.file = f
	l.size = 0
}

// LogPath returns the expected log file path for a given port.
func LogPath(port int) string {
	return fmt.Sprintf("logs/proxy_%d.log", port)
}
