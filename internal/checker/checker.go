package checker

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/ITA-Dnipro/Dp-230_Test_Sql_Injection/internal/htmlForm"
	"github.com/go-resty/resty/v2"
	"golang.org/x/net/html"
)

// Checker defines error based sqli checker for bWAPP.
type Checker interface {
	Start() Checker
	Check(link string) error
}

type checker struct {
	payload    string
	errors     []string
	errRegexes []*regexp.Regexp
	client     *resty.Client
}

func New(payload string, errors []string, client *resty.Client) Checker {
	c := &checker{
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

// Start firstly gets valid cookies for bwapp.
func (c *checker) Start() Checker {
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

	//TODO: add kafka worker. Here we'll get a URL.
	return c
}

// Check firstly reads payloads from the file, then creates regexp for errors, after gets site body
// checking it on possible inclusions of error keywords, finally posts htmlForm on site with injectable parameters.
// Having this done matches response body with possible error keywords.
func (c *checker) Check(link string) error {
	f, err := os.Open(c.payload)
	if err != nil {
		return fmt.Errorf("sorry could not parse the list ->  %v\n", c.payload)
	}
	defer f.Close()

	forms, countBefore, err := c.fetchForms(link)
	fmt.Println("Forms received...")
	if err != nil {
		return err
	}
	var wg sync.WaitGroup

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		payload := scan.Text()
		wg.Add(1)
		go c.submitForm(link, payload, countBefore, forms, setValues, &wg)
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

//fetchForms fetches all forms which are exists in given link.
func (c *checker) fetchForms(link string) ([]*htmlForm.HtmlForm, int, error) {
	resp, err := c.client.R().Get(link)
	if err != nil {
		return nil, 0, fmt.Errorf("error fetching url %q: %v", link, err)
	}

	root, err := html.Parse(bytes.NewReader(resp.Body()))
	if err != nil {
		return nil, 0, fmt.Errorf("error parsing response: %v", err)
	}

	forms := htmlForm.ParseForms(root)

	if len(forms) == 0 {
		return nil, 0, fmt.Errorf("no forms found at %q", link)
	}

	for _, f := range forms {
		err := f.ParseURL(link)
		if err != nil {
			return forms, 0, err
		}
	}

	countBefore := c.countErrs(resp.Body())

	return forms, countBefore, nil
}

// submitForm submitting htmlForm putting each payload. Matches request body with possible errors.
func (c *checker) submitForm(link, payload string, countBefore int, forms []*htmlForm.HtmlForm, setValues func(url.Values, string), wg *sync.WaitGroup) {
	defer wg.Done()

	for _, f := range forms {
		// filling the form empty attributes with payloads
		if setValues != nil {
			setValues(f.Values, payload)
		}

		resp, err := c.client.R().
			SetFormDataFromValues(f.Values).
			Post(f.GetURL())
		if err != nil {
			log.Printf("error posting htmlForm: %v", err)
		}

		countAfter := c.countErrs(resp.Body())

		for i, re := range c.errRegexes {
			if re.MatchString(string(resp.Body())) && countBefore != countAfter {
				fmt.Printf("FOUND VULNARABILITY IN [%s] TO PAYLOAD [%s] IN URL [%s] IN FORM[%v]\n", c.errors[i], payload, link, f)
				break
			}
		}
	}
}

// setValues sets given payload whether field is empty.
func setValues(values url.Values, payload string) {
	for k, v := range values {
		for _, i := range v {
			if i == "" {
				values.Set(k, payload)
			}
		}
	}
}
