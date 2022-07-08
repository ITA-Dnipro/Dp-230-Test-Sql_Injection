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

	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/config"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/broker"
	"github.com/ITA-Dnipro/Dp-230-Test-Sql_Injection/internal/form"
	"github.com/go-resty/resty/v2"

	"golang.org/x/exp/slices"
	"golang.org/x/net/html"
)

// Checker defines error based sqli checker for bWAPP.
type Checker interface {
	Start()
	ErrorBasedCheck(link string) error
}

type checker struct {
	errors     []string
	errRegexes []*regexp.Regexp
	client     *resty.Client
	config     config.Config
	consumer   *broker.Consumer
}

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

// Start firstly gets valid cookies for bwapp.
func (c *checker) Start() {
	c.authLocal()
	//ctx := context.Background()
	//TODO: add kafka worker. Here we'll get a URL.

	//for {
	//	// the `ReadMessage` method blocks until we receive the next event
	//	//msg, err := c.consumer.Reader.ReadMessage(ctx)
	//	//if err != nil {
	//	//	log.Fatalf("could not read message: %v ", err)
	//	//}
	//	message, err := c.consumer.FetchMessage(ctx)
	//	if err != nil {
	//		log.Printf("Error fetching message: %v\n", err)
	//	}
	//	for _, url := range message.Value.URLs {
	//		err := c.ErrorBasedCheck(url)
	//		if err != nil {
	//			log.Printf("Error-based check error:%v\n", err)
	//		}
	//	}
	//}
	fmt.Println(c.ErrorBasedCheck("http://localhost/sqli_16.php"))
}

// ErrorBasedCheck firstly reads payloads from the file, then creates regexp for errors, after gets site body
// checking it on possible inclusions of error keywords, finally posts form on site with injectable parameters.
// Having this done matches response body with possible error keywords.
func (c *checker) ErrorBasedCheck(link string) error {
	f, err := os.Open(c.config.Checker.ErrBasedPayload)
	if err != nil {
		return fmt.Errorf("sorry could not parse the list ->  %v\n", c.config.Checker.ErrBasedPayload)
	}
	defer f.Close()

	forms, countBefore, err := c.fetchForms(link)
	fmt.Printf("Forms received... Len: %d\n", len(forms))
	if err != nil {
		return err
	}
	var wg sync.WaitGroup

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		payload := scan.Text()
		tmp := slices.Clone(forms)
		for _, v := range tmp {
			for k, i := range v.Values {
				for _, p := range i {
					if p == "" {
						v.Values.Set(k, payload)
					}
				}
			}
		}
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
func (c *checker) fetchForms(link string) ([]form.HtmlForm, int, error) {
	resp, err := c.client.R().Get(link)
	if err != nil {
		return nil, 0, fmt.Errorf("error fetching url %q: %w", link, err)
	}
	//b := bytes.NewReader(resp.Body())
	root, err := html.Parse(bytes.NewReader(resp.Body()))
	if err != nil {
		return nil, 0, fmt.Errorf("error parsing response: %w", err)
	}

	forms := form.ParseForms(root, link)

	if len(forms) == 0 {
		return nil, 0, fmt.Errorf("no forms found at %q", link)
	}

	countBefore := c.countErrs(resp.Body())

	return forms, countBefore, nil
}

// submitForm submitting form putting each payload. Matches request body with possible errors.
func (c *checker) submitForm(link, payload string, countBefore int, forms []form.HtmlForm, setValues func(url.Values, string), wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("VALUES: %v\n", forms[0].Values)

	tmp := slices.Clone(forms)
	fmt.Printf("TMP len: %v", len(tmp))

	for _, f := range tmp {
		//filling the form empty attributes with payloads
		if setValues != nil {
			setValues(f.Values, payload)
		}

		fmt.Printf("Values after:%v\n", f.Values)
		fmt.Printf("PAYLOAD:%v", payload)

		resp, err := c.client.R().
			SetFormDataFromValues(f.Values).
			Post(f.URL)
		if err != nil {
			log.Printf("error posting form: %v", err)
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
