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
	"time"

	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/config"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/broker"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/form"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/result"

	"github.com/go-resty/resty/v2"
)

// Checker defines sql-injection checker methods.
type Checker interface {
	Start()
	ErrorBasedCheck(link string) ([]string, error)
}

// checker defines sql-injection checker.
type checker struct {
	errors     []string
	errRegexes []*regexp.Regexp
	httpClient *resty.Client
	grpcClient result.CheckerClient
	config     config.Config
	consumer   *broker.Consumer
}

// New creates a new instance of checker.
func New(errors []string) Checker {
	httpClient := resty.New()
	conf := config.New()
	reader := broker.New(conf)
	grpcClient := result.New(conf)
	c := &checker{
		errors:     errors,
		httpClient: httpClient,
		config:     conf,
		consumer:   reader,
		grpcClient: grpcClient,
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
		result := c.processMessage(message)
		result.Result = deleteEmpty(result.Result)
		if len(result.Result) == 0 {
			result.Result = append(result.Result, "SQLi-check: No vulnerabilities found.")
		}
		err = c.sendResult(result)
		if err != nil {
			log.Println(err)
		} else {
			log.Printf("Results have been successfully sent to Result Collector.")
		}

	}
}

// processMessage starts checking given list of url, appending results received.
func (c *checker) processMessage(m broker.Message) *result.Result {
	results := make([]string, 0)
	totalResult := result.Result{TaskID: m.Value.ID, Result: make([]string, 0)}

	for _, url := range m.Value.URLs {
		res, err := c.ErrorBasedCheck(url)
		if err != nil {
			log.Printf("Error-based check:%v\n", err)
		}
		results = append(results, res...)
	}
	totalResult.Result = append(totalResult.Result, results...)
	return &totalResult
}

// sendResult sends given results via gRPC.
func (c *checker) sendResult(r *result.Result) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := c.grpcClient.SendResult(ctx, &result.ResultRequest{ResultData: r})
	if err != nil {
		return fmt.Errorf("Error sending result %v\n", err)
	}

	return nil
}

// ErrorBasedCheck firstly reads payloads from the file, then creates regexp for errors, after gets site body
// checking it on possible inclusions of error keywords, finally posts form on site with injectable parameters.
// Having this done matches response body with possible error keywords.
func (c *checker) ErrorBasedCheck(link string) ([]string, error) {
	results := make([]string, 0)
	// reading file with payloads with path from config.
	f, err := os.Open(c.config.Checker.ErrBasedPayload)
	if err != nil {
		return results, fmt.Errorf("sorry could not parse the list ->  %v\n", c.config.Checker.ErrBasedPayload)
	}
	defer f.Close()

	// getting forms by the given url.
	forms, countBefore, err := c.fetchForms(link)
	log.Printf("Number of forms received: %d\n", len(forms))
	if err != nil {
		return results, err
	}

	var wg sync.WaitGroup
	res := make(chan []string)

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		payload := scan.Text()
		wg.Add(1)
		go func() {
			res <- c.submitForm(link, payload, countBefore, forms)
		}()
	}
	go func() {
		for r := range res {
			results = append(results, r...)
			wg.Done()
		}
	}()

	wg.Wait()
	close(res)

	fmt.Printf("Finished with url: %v !\n", link)
	return results, nil
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
	resp, err := c.httpClient.R().Get(link)
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
func (c *checker) submitForm(link, payload string, countBefore int, forms []form.HtmlForm) []string {
	results := make([]string, 0)

	for _, f := range forms {
		formValues := copyMap(f.Values)
		setValues(formValues, payload)

		resp, err := c.httpClient.R().
			SetFormData(formValues).
			Post(f.URL)
		if err != nil {
			log.Printf("error posting form: %v", err)
		}

		countAfter := c.countErrs(resp.Body())
		body := string(resp.Body())
		for i, re := range c.errRegexes {
			if re.MatchString(body) && countBefore != countAfter {
				results = append(results, fmt.Sprintf("FOUND VULNARABILITY IN [%s] TO PAYLOAD [%s] IN URL [%s]\n", c.errors[i], payload, link))
				break
			}
		}
	}
	return results
}

// authLocal is the authentication in case we have bWAPP-site started locally.
func (c *checker) authLocal() {
	_, err := c.httpClient.R().
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
