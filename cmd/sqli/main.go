package main

import (
	"context"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/broker"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/checker"
	"log"
)

var (
	errors = []string{
		"SQL",
		"MySQL",
		"syntax",
	}
	url = "http://localhost/sqli_16.php"
)

func main() {
	c := checker.New(errors)
	//fakeProducer()
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
