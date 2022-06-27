package main

import (
	"github.com/ITA-Dnipro/Dp-230_Test_Sql_Injection/internal"
	"github.com/go-resty/resty/v2"
)

var errors = []string{
	"SQL",
	"MySQL",
	"ORA-",
	"syntax",
}

var url = "http://localhost/sqli_16.php"

func main() {
	client := resty.New()
	checker := internal.NewChecker(url, "../../asset/payload.txt", errors, client)
	checker.BWAPPAuth().Check()
}
