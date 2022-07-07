package broker

import "time"

type Message struct {
	Key   string
	Value *Task
	Time  time.Time
}

type Task struct {
	ID   string   `json:"id"`
	URLs []string `json:"urls"`
}
