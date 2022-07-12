// Package form provides methods for parsing all appropriate forms by the given link.
package form

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// HtmlForm represents needed elements of an HTML Form.
type HtmlForm struct {
	// Action parsed from action form's field
	Action string
	// URL is the complete url where form will be posted
	URL string
	// Values contains form values to be submitted
	Values map[string]string
}

// ParseForms parses and returns all form elements beneath given io.Reader. Form values
// include all input, select with the first possible value and submit buttons. The values of radio
// and checkbox inputs are included only if they are checked.
func ParseForms(r io.Reader, link string) (forms []HtmlForm) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		log.Println(err)
		return nil
	}
	doc.Find("form").Each(func(_ int, s *goquery.Selection) {
		form := HtmlForm{Values: make(map[string]string)}
		form.Action, _ = s.Attr("action")
		err := form.parseURL(link)
		if err != nil {
			log.Printf("Error parsing URL: %v", err)
		}

		_, ok := s.Find("input").Attr("type")
		if ok {
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
				form.Values[name] = value
			})
			s.Find("select").Each(func(_ int, s *goquery.Selection) {
				name, _ := s.Attr("name")
				if name == "" {
					return
				}

				value, _ := s.Find("option").First().Attr("value")
				form.Values[name] = value
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
				form.Values[name] = value
			})
			forms = append(forms, form)
		}
	})
	return forms
}

//parseURL parses form's action url to the site's domain name.
func (f *HtmlForm) parseURL(link string) error {
	actionURL, err := url.Parse(f.Action)
	if err != nil {
		return fmt.Errorf("error parsing form action URL %q: %w", f.Action, err)
	}
	pageUrl, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("error parsing page URL %q: %w", link, err)
	}
	actionURL = pageUrl.ResolveReference(actionURL)
	f.URL = pageUrl.String()

	return nil
}
