package checker

import "testing"

func TestCountErrs(t *testing.T) {
	c := new(checker)
	c.errors = []string{"set", "SQL"}
	bodySet := []byte("setup on saturn set universe settings set")
	bodySQL := []byte("injected parameter have to break SQL code, then")

	set := c.countErrs(bodySet)
	sql := c.countErrs(bodySQL)

	if set != 4 {
		t.Errorf("we expect 4 inclusions")
	}
	if sql != 1 {
		t.Errorf("we expect 1 SQL inlision")
	}
}
