package checker

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
	Start() Checker
	Check()
}

type checker struct {
	url        string
	payload    string
	errors     []string
	errRegexes []*regexp.Regexp
	client     *resty.Client
}

func New(url, payload string, errors []string, client *resty.Client) Checker {
	c := &checker{
		url:     url,
		payload: payload,
		errors:  errors,
		client:  client,
	}

	for _, e := range c.errors {
		re := regexp.MustCompile(fmt.Sprintf(".*%s.*", e))
		c.errRegexes = append(c.errRegexes, re)
	}

	return c
}

// Start gets valid cookies for bWAPP-site. Therefore
func (c *checker) Start() Checker {
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

	//TODO: add kafka worker.
	return c
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

		// send GET request to get body of a page before sending form.
		// Page may have keywords of SQL errors.
		resp, err := c.client.R().Get(c.url)
		if err != nil {
			log.Printf("Couldn't send get request: %v\n", err)
			break
		}
		countBefore := c.countErrs(resp.Body())
		var wg sync.WaitGroup

		for _, payload := range payloads {
			wg.Add(1)
			go c.formSubmit(&wg, payload, countBefore)
		}
		wg.Wait()
	}
}

// countErrs counts inclusions of errors from checker error-list if they are existed.
func (c *checker) countErrs(bytes []byte) int {
	var count = 0
	body := string(bytes)
	for _, err := range c.errors {
		count += strings.Count(body, err)
	}

	return count
}

// formSubmit submitting form putting each payload. Matches request body with possible errors.
func (c *checker) formSubmit(wg *sync.WaitGroup, payload string, countBefore int) {
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
	countAfter := c.countErrs(resp.Body())

	for i, re := range c.errRegexes {
		if re.MatchString(string(resp.Body())) && countBefore != countAfter {
			fmt.Printf("FOUND VULNARABILITY IN [%s] TO PAYLOAD [%s] IN URL [%s]\n", c.errors[i], payload, c.url)
			break
		}
	}
}
