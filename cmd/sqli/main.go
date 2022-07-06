package main

import (
	"fmt"
	"github.com/ITA-Dnipro/Dp-230_Test_Sql_Injection/internal/checker"
	"github.com/go-resty/resty/v2"
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
	client := resty.New()
	checker := checker.New("../../asset/payload.txt", errors, client)
	if err := checker.Start().Check("https://szsh21.klasna.com/"); err != nil {
		fmt.Println(err)
	}
}
