package broker

import "time"

// Message is a struct describes message got from Kafka.
type Message struct {
	Key   string
	Value Task
	Time  time.Time
}

// Task is a struct with Task ID and list of url to check.
type Task struct {
	ID   string   `json:"id"`
	URLs []string `json:"urls"`
}
