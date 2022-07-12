// Package checker contains checker definition and all it's methods.
package checker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/config"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/broker"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/form"
	"github.com/go-resty/resty/v2"
)

// Checker defines sql-injection checker methods.
type Checker interface {
	Start()
	ErrorBasedCheck(link string) error
}

// checker defines sql-injection checker.
type checker struct {
	errors     []string
	errRegexes []*regexp.Regexp
	client     *resty.Client
	config     config.Config
	consumer   *broker.Consumer
}

// New creates a new instance of checker.
func New(errors []string) Checker {
	client := resty.New()
	conf := config.New()
	reader := broker.New(conf)
	c := &checker{
		errors:   errors,
		client:   client,
		config:   conf,
		consumer: reader,
	}

	for _, e := range c.errors {
		re := regexp.MustCompile(fmt.Sprintf(".*%s.*", e))
		c.errRegexes = append(c.errRegexes, re)
	}

	return c
}

// Start starts checker with initial authentication on bWAPP vulnerable container running in docker.
// Then waiting for kafka's income messages in a loop. Having them it starts error-based sql-injection check.
func (c *checker) Start() {
	c.authLocal()
	ctx := context.Background()

	for {
		message, err := c.consumer.FetchMessage(ctx)
		if err != nil {
			log.Printf("Error fetching message: %v\n", err)
		}
		for _, url := range message.Value.URLs {
			err := c.ErrorBasedCheck(url)
			if err != nil {
				log.Printf("Error-based check error:%v\n", err)
			}
		}
		// set it to nil for stop processing previous result while no messages from Kafka.
	}
}

// ErrorBasedCheck firstly reads payloads from the file, then creates regexp for errors, after gets site body
// checking it on possible inclusions of error keywords, finally posts form on site with injectable parameters.
// Having this done matches response body with possible error keywords.
func (c *checker) ErrorBasedCheck(link string) error {
	// reading file with payloads with path from config.
	f, err := os.Open(c.config.Checker.ErrBasedPayload)
	if err != nil {
		return fmt.Errorf("sorry could not parse the list ->  %v\n", c.config.Checker.ErrBasedPayload)
	}
	defer f.Close()

	// getting forms by the given url.
	forms, countBefore, err := c.fetchForms(link)
	log.Printf("Number of forms received: %d\n", len(forms))
	if err != nil {
		return err
	}
	var wg sync.WaitGroup

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		payload := scan.Text()
		wg.Add(1)
		go c.submitForm(link, payload, countBefore, forms, &wg)
	}
	wg.Wait()
	fmt.Println("Finished!")
	return nil
}

// countErrs counts inclusions of errors from checker error-list if they are existed.
func (c *checker) countErrs(bytes []byte) int {
	var counter = 0
	body := string(bytes)
	for _, err := range c.errors {
		counter += strings.Count(body, err)
	}

	return counter
}

//fetchForms fetches all forms which existed on a web-page by given link.
func (c *checker) fetchForms(link string) ([]form.HtmlForm, int, error) {
	resp, err := c.client.R().Get(link)
	if err != nil {
		return nil, 0, fmt.Errorf("error fetching url %q: %w", link, err)
	}

	b := bytes.NewReader(resp.Body())
	forms := form.ParseForms(b, link)

	if len(forms) == 0 {
		return nil, 0, fmt.Errorf("no forms found at %q", link)
	}

	countBefore := c.countErrs(resp.Body())

	return forms, countBefore, nil
}

// submitForm submitting form putting each payload. Matches request body with possible errors.
func (c *checker) submitForm(link, payload string, countBefore int, forms []form.HtmlForm, wg *sync.WaitGroup) {
	defer wg.Done()

	for _, f := range forms {
		formValues := copyMap(f.Values)
		setValues(formValues, payload)

		resp, err := c.client.R().
			SetFormData(formValues).
			Post(f.URL)
		if err != nil {
			log.Printf("error posting form: %v", err)
		}

		countAfter := c.countErrs(resp.Body())
		body := string(resp.Body())
		for i, re := range c.errRegexes {
			if re.MatchString(body) && countBefore != countAfter {
				fmt.Printf("FOUND VULNARABILITY IN [%s] TO PAYLOAD [%s] IN URL [%s]\n", c.errors[i], payload, link)
				break
			}
		}
	}
}

// authLocal is the authentication in case we have bWAPP-site started locally.
func (c *checker) authLocal() {
	_, err := c.client.R().
		SetFormData(map[string]string{
			"login":    "admin",
			"password": "12345",
			"form":     "submit",
		}).
		Post("http://localhost/login.php")

	if err != nil {
		log.Printf("Could'n get cookies for bWAPP:%v\n", err)
	}
}

// setValues assigns the payload to an empty form's attribute.
func setValues(v map[string]string, payload string) {
	for k, val := range v {
		if val == "" {
			v[k] = payload
		}
	}
}

// copyMap copies values of the entire map into the new one.
func copyMap(m map[string]string) map[string]string {
	m2 := make(map[string]string, len(m))
	for k, v := range m {
		m2[k] = v
	}

	return m2
}
