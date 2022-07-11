// Package main creates and starts a new checker. Now it has a fakeProducer function, for testing.
package main

import (
	"context"
	"log"

	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/broker"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/checker"
)

var (
	errors = []string{
		"SQL",
		"MySQL",
		"syntax",
	}
)

func main() {
	c := checker.New(errors)
	fakeProducer()
	c.Start()
}

//fakeProducer just for testing msg publishing
func fakeProducer() {
	ctx := context.Background()
	b := broker.NewProducer("localhost:9092", "sqli-check")
	m := broker.NewMessageProduce("1313", []string{"http://localhost/sqli_16.php", "https://school39.klasna.com/"})
	err := b.PublicMessage(ctx, m)
	if err != nil {
		log.Println(err)
	}
}
