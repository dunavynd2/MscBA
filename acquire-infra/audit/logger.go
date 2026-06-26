package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Logger writes newline-delimited JSON audit records to a file.
// Each record is fsync-free (OS buffering) — mount the log volume on
// a separate filesystem if you need durability guarantees.
type Logger struct {
	f *os.File
}

// Entry is one audit record. Fields are omitted when empty.
type Entry struct {
	Timestamp string `json:"ts"`
	Event     string `json:"event"`
	Chain     string `json:"chain,omitempty"`
	TxHash    string `json:"tx_hash,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Value     string `json:"value,omitempty"`
	Error     string `json:"error,omitempty"`
}

func New(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{f: f}, nil
}

func (l *Logger) Log(e Entry) {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit marshal: %v\n", err)
		return
	}
	data = append(data, '\n')
	if _, err := l.f.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "audit write: %v\n", err)
	}
}

func (l *Logger) Close() error {
	return l.f.Close()
}
