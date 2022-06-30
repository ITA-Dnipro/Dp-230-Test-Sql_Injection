package main

import (
	"github.com/ITA-Dnipro/Dp-230_Test_Sql_Injection/internal/checker"
	"github.com/go-resty/resty/v2"
)

var (
	errors = []string{
		"SQL",
		"MySQL",
		"ORA-",
		"syntax",
	}
	url = "http://localhost/sqli_16.php"
)

func main() {
	client := resty.New()
	checker := checker.New(url, "../../asset/payload.txt", errors, client)
	checker.Start().Check()
}
