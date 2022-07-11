package htmlForm

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

// HtmlForm represents needed elements of an HTML Form.
type HtmlForm struct {
	// Action parsed from action form's field
	Action string
	// URL is the complete url where form will be posted
	URL string
	// Values contains htmlForm values to be submitted
	Values url.Values
}

// ParseForms parses and returns all htmlForm elements beneath node.  Form values
// include all input, select with the first possible value and submit buttons. The values of radio
// and checkbox inputs are included only if they are checked.
func ParseForms(node *html.Node) (forms []*HtmlForm) {
	if node == nil {
		return nil
	}

	doc := goquery.NewDocumentFromNode(node)
	doc.Find("form").Each(func(_ int, s *goquery.Selection) {
		form := &HtmlForm{Values: url.Values{}}
		form.Action, _ = s.Attr("action")

		s.Find("input").Each(func(_ int, s *goquery.Selection) {
			name, _ := s.Attr("name")
			if name == "" {
				return
			}

			typ, _ := s.Attr("type")
			typ = strings.ToLower(typ)
			_, checked := s.Attr("checked")
			if (typ == "radio" || typ == "checkbox") && !checked {
				return
			}

			value, _ := s.Attr("value")
			form.Values.Add(name, value)
		})
		// if form has no inputs it's not interesting to us
		_, ok := s.Find("input").Attr("type")
		if ok {
			s.Find("select").Each(func(_ int, s *goquery.Selection) {
				name, _ := s.Attr("name")
				if name == "" {
					return
				}

				value, _ := s.Find("option").First().Attr("value")
				form.Values.Add(name, value)
			})
			s.Find("button").Each(func(_ int, s *goquery.Selection) {
				name, _ := s.Attr("name")
				if name == "" {
					return
				}

				typ, _ := s.Attr("type")
				typ = strings.ToLower(typ)
				if typ != "submit" {
					return
				}

				value, _ := s.Attr("value")
				form.Values.Add(name, value)
			})
		}
		forms = append(forms, form)
		fmt.Println(form)
	})
	return forms
}

func (f *HtmlForm) ParseURL(link string) error {
	actionURL, err := url.Parse(f.Action)
	if err != nil {
		return fmt.Errorf("error parsing form action URL %q: %v", f.Action, err)
	}
	pageUrl, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("error parsing page URL %q: %v", link, err)
	}
	actionURL = pageUrl.ResolveReference(actionURL)
	f.setURL(actionURL)

	return nil
}

func (f *HtmlForm) GetURL() string {
	return f.URL
}

func (f *HtmlForm) setURL(url *url.URL) {
	f.URL = url.String()
}
