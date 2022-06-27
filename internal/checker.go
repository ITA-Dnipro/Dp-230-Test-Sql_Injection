package internal

import (
	"bufio"
	"fmt"
	"github.com/go-resty/resty/v2"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Checker defines error based sqli checker for bWAPP.
type Checker interface {
	BWAPPAuth() Checker
	CountErrs(body []byte) int
	Check()
}

type checker struct {
	url     string
	payload string
	errors  []string
	client  *resty.Client
}

func NewChecker(url, payload string, errors []string, client *resty.Client) Checker {
	c := &checker{
		url:     url,
		payload: payload,
		errors:  errors,
		client:  client,
	}

	return c
}

// BWAPPAuth gets valid cookies for bWAPP-site.
func (c *checker) BWAPPAuth() Checker {
	_, err := c.client.R().
		SetFormData(map[string]string{
			"login":          "admin",
			"password":       "12345",
			"security_level": "0",
			"form":           "submit",
		}).
		Post("http://localhost/login.php")

	if err != nil {
		log.Printf("Could'n get cookies for bWAPP:%v\n", err)
	}

	return c
}

// CountErrs counts inclusions of errors from checker error-list if they are existed.
func (c *checker) CountErrs(body []byte) int {
	var count = 0
	for _, err := range c.errors {
		count += strings.Count(string(body), err)
	}

	return count
}

// Check firstly reads payloads from the file, then creates regexp for errors, after gets site body
// checking it on possible inclusions of error keywords, finally posts form on site with injectable parameters.
// Having this done matches response body with possible error keywords.
func (c *checker) Check() {
	f, err := os.Open(c.payload)
	if err != nil {
		fmt.Println("Sorry could not parse the list -> ", c.payload)
		return
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		payloads := []string{
			scan.Text(),
		}
		// create a matching list with checker errors set.
		var errRegexes []*regexp.Regexp
		for _, e := range c.errors {
			re := regexp.MustCompile(fmt.Sprintf(".*%s.*", e))
			errRegexes = append(errRegexes, re)
		}

		resp, err := c.client.R().Get(c.url)
		if err != nil {
			log.Printf("Couldn't send get request: %v\n", err)
			break
		}
		countBefore := c.CountErrs(resp.Body())
		var wg sync.WaitGroup

		for _, payload := range payloads {
			wg.Add(1)
			payload := payload
			go func() {
				defer wg.Done()
				resp, err := c.client.R().
					SetFormData(map[string]string{
						"login":    payload,
						"password": "12345",
						"form":     "submit",
					}).
					Post(c.url)
				if err != nil {
					log.Printf("Error sending form data : %v\n", err)
				}

				countAfter := c.CountErrs(resp.Body())

				for i, re := range errRegexes {
					if re.MatchString(string(resp.Body())) && countBefore != countAfter {
						fmt.Printf("FOUND VULNARABILITY IN [%s] TO PAYLOAD [%s] IN URL [%s]\n", c.errors[i], payload, c.url)
						break
					}
				}
			}()
		}
		wg.Wait()
	}
}
