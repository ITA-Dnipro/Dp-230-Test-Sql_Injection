// Package config has configs for the application.
package config

import (
	"context"
	"log"

	"github.com/sethvargo/go-envconfig"
)

// Config takes config parameters from environment, or uses default.
type Config struct {
	Kafka      *KafkaConfig
	Checker    *CheckerConfig
	GRPCConfig *GRPCConfig
}

// KafkaConfig include parameters for Kafka.
type KafkaConfig struct {
	Brokers []string `env:"KAFKA_BROKERS, default=localhost:9092"`
	GroupID string   `env:"KAFKA_CONSUMER_GROUP_ID, default=sqli"`
	Topic   string   `env:"KAFKA_SQLI_TOPIC, default=sqli-check"`
}

// CheckerConfig include parameters for checker.
type CheckerConfig struct {
	ErrBasedPayload  string `env:"ERROR_BASED_PAYLOAD_PATH, default=./asset/errorbased.txt"`
	TimeBasedPayload string `env:"TIME_BASED_PAYLOAD_PATH, default=./asset/timebased.txt"`
}

type GRPCConfig struct {
	ResultCollectorAddress string `env:"RESULT_COLLECTOR_PORT, default=localhost:50001"`
}

// New returns new config.
func New() Config {
	ctx := context.Background()

	var c Config
	if err := envconfig.Process(ctx, &c); err != nil {
		log.Fatal(err)
	}

	return c
}
