package runtimeevents

import "time"

type Event struct {
	Type      string            `json:"type"`
	Source    string            `json:"source,omitempty"`
	PodName   string            `json:"podName,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Timestamp time.Time         `json:"timestamp,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func (e Event) Field(key string) string {
	if e.Fields == nil {
		return ""
	}
	return e.Fields[key]
}
