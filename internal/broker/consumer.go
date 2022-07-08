package broker

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/config"
	"github.com/segmentio/kafka-go"
)

type Consumer struct {
	Reader *kafka.Reader
}

func New(conf config.Config) *Consumer {
	l := log.New(os.Stdout, "kafka reader: ", 0)
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     conf.Kafka.Brokers,
		Topic:       conf.Kafka.Topic,
		GroupID:     conf.Kafka.GroupID,
		StartOffset: kafka.FirstOffset,
		Logger:      l,
		MaxAttempts: 5,
	})

	c := &Consumer{Reader: r}

	return c
}

func (cons *Consumer) FetchMessage(ctx context.Context) (*Message, error) {
	message := &Message{}

	msg, err := cons.Reader.FetchMessage(ctx)
	if err != nil {
		return message, err
	}

	task := &Task{}
	err = json.Unmarshal(msg.Value, task)
	if err != nil {
		return message, err
	}
	message.Key = string(msg.Key)
	message.Value = task
	message.Time = msg.Time

	log.Println("Read from Kafka. Task ID:", message.Value.ID)

	return message, nil
}
