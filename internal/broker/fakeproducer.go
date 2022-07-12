// Package broker this package just for testing publishing messages
package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

type MessageProduce struct {
	Key   string
	Value *TaskProduce
	Time  time.Time
}

type TaskProduce struct {
	ID   string   `json:"id"`
	URLs []string `json:"urls"`
}

func NewMessageProduce(taskID string, urls []string) *MessageProduce {
	tsk := &TaskProduce{
		ID:   taskID,
		URLs: urls,
	}

	return &MessageProduce{
		Key:   fmt.Sprint(uuid.New()),
		Value: tsk,
		Time:  time.Now(),
	}
}

type Producer struct {
	kafkaWriter *kafka.Writer
}

func NewProducer(url, topic string) *Producer {
	result := new(Producer)
	result.kafkaWriter = &kafka.Writer{
		Addr:     kafka.TCP(url),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
	}

	return result
}

func (prod *Producer) PublicMessage(ctx context.Context, message *MessageProduce) error {
	valueJson, err := json.Marshal(message.Value)
	if err != nil {
		log.Printf("Error marshalling %v to json: %v\n", message.Value, err)

		return err
	}

	msg := kafka.Message{
		Key:   []byte(message.Key),
		Value: valueJson,
		Time:  message.Time,
	}

	log.Println("Publishing into Kafka topic:", prod.kafkaWriter.Topic)
	msgOut := string(msg.Value)
	if len(msgOut) > 250 {
		msgOut = msgOut[:250] + "\t..."
	}
	log.Println("\t", msgOut)

	return prod.kafkaWriter.WriteMessages(ctx, msg)
}

func (prod *Producer) Close() error {
	return prod.kafkaWriter.Close()
}
