package hcl

import (
	"fmt"
	"reflect"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/pantry"
)

// convertFn is a seam. The two guards below protect against a defect in the
// renderer, so nothing reachable through the public API can trigger them while
// the renderer is correct — and between them they caught a heredoc terminator
// colliding with a script's own EOT line. A test reaches them by substituting
// a conversion that is wrong on purpose.
var convertFn = bottle.YAMLToHCL

// Convert turns a package.yml into package.hcl text, and refuses to return
// text that does not parse back into the same recipe.
//
// The RENDERING is bottle.YAMLToHCL — the same conversion the client runs on
// upstream recipes as they arrive, which is what makes this command a
// measurement of the shipping path rather than of a copy of it. A second
// renderer here would drift, and the two would disagree about a recipe on the
// day it mattered.
//
// What bk adds is the comparison the client cannot make. bottle checks that
// the HCL reads back as the same DOCUMENT; only bk has pantry.Parse, so only
// bk can check that it reads back as the same RECIPE — which is what a build
// actually consumes, and where the schema has its say.
func Convert(yamlSrc []byte) ([]byte, error) {
	out, err := convertFn(yamlSrc, "package.yml")
	if err != nil {
		return nil, err
	}
	want, err := pantry.Parse(yamlSrc)
	if err != nil {
		return nil, fmt.Errorf("the yaml does not parse: %w", err)
	}
	got, err := Parse(out, "package.hcl")
	if err != nil {
		return nil, fmt.Errorf("the hcl this produced does not parse: %w", err)
	}
	// The VERDICT and the EXPLANATION are the same comparison.
	//
	// They were not: the decision was reflect.DeepEqual and the message came
	// from firstDiff, so once firstDiff learned that two numbers rendering the
	// same text are the same, four recipes were refused with an empty
	// explanation — "is a DIFFERENT recipe:" and nothing after the colon. A
	// check whose reason disagrees with its answer cannot be acted on.
	if d := firstDiff(want, got, ""); d != "" {
		// Naming the PATH, not printing both recipes. The first version dumped
		// them with %#v and they came out character-identical, because %#v
		// renders int(1) and float64(1) the same way — the difference was a
		// type, and the message could not show it.
		return nil, fmt.Errorf("the hcl this produced is a DIFFERENT recipe: %s", d)
	}
	return out, nil
}

// firstDiff walks two decoded recipes and describes the first place they part,
// with the TYPES — which is where the differences live. A YAML decode gives
// int for a whole number; a cty value gives float64, and %#v prints both as
// "1".
func firstDiff(a, b any, path string) string {
	if path == "" {
		path = "."
	}
	ra, rb := reflect.ValueOf(a), reflect.ValueOf(b)
	if ra.IsValid() != rb.IsValid() {
		return fmt.Sprintf("%s: one side is absent", path)
	}
	if !ra.IsValid() {
		return ""
	}
	if ra.Kind() == reflect.Ptr && rb.Kind() == reflect.Ptr {
		// Both nil is EQUAL. The first version reported "<nil> vs <nil>" as a
		// difference, so every recipe with an absent `runtime:` — which is
		// most of them — would have been refused for differing from itself.
		// A test comparing a recipe with itself is what found it.
		if ra.IsNil() && rb.IsNil() {
			return ""
		}
		if ra.IsNil() || rb.IsNil() {
			return fmt.Sprintf("%s: %v vs %v", path, a, b)
		}
		return firstDiff(ra.Elem().Interface(), rb.Elem().Interface(), path)
	}
	if ra.Kind() == reflect.Struct && rb.Kind() == reflect.Struct && ra.Type() == rb.Type() {
		for i := 0; i < ra.NumField(); i++ {
			if !ra.Type().Field(i).IsExported() {
				continue
			}
			if d := firstDiff(ra.Field(i).Interface(), rb.Field(i).Interface(), path+"."+ra.Type().Field(i).Name); d != "" {
				return d
			}
		}
		return ""
	}
	if ra.Type() != rb.Type() {
		// Two numbers that RENDER the same are the same, whatever Go type they
		// arrived as.
		//
		// HCL has one number type, so a YAML float64(11) comes back as
		// int64(11) and the structs differ. The build does not: every numeric
		// value reaches a script through transformScalar's fmt.Sprint, and
		// both render "11". Measured rather than argued — the four recipes
		// this affects (apache.org/thrift, isc.org/bind9, mpv.io,
		// pwmt.org/zathura) generate byte-identical build scripts from either
		// recipe.
		//
		// It stays narrow on purpose. Both sides must be numeric, so a string
		// "11" is still not the number 11; and the texts must match, so
		// float64(2.0250127e+07) is still not int64(20250127) — which is a
		// REAL difference, and the one that turned out to be a client bug.
		if numericKind(ra.Kind()) && numericKind(rb.Kind()) && fmt.Sprint(a) == fmt.Sprint(b) {
			return ""
		}
		return fmt.Sprintf("%s: %T(%v) from yaml, %T(%v) from hcl", path, a, a, b, b)
	}
	switch ra.Kind() {
	case reflect.Map:
		for _, k := range ra.MapKeys() {
			vb := rb.MapIndex(k)
			if !vb.IsValid() {
				return fmt.Sprintf("%s[%v]: present in the yaml, absent from the hcl", path, k)
			}
			if d := firstDiff(ra.MapIndex(k).Interface(), vb.Interface(), fmt.Sprintf("%s[%v]", path, k)); d != "" {
				return d
			}
		}
		for _, k := range rb.MapKeys() {
			if !ra.MapIndex(k).IsValid() {
				return fmt.Sprintf("%s[%v]: the hcl invented it", path, k)
			}
		}
		return ""
	case reflect.Slice:
		if ra.Len() != rb.Len() {
			return fmt.Sprintf("%s: %d items from yaml, %d from hcl", path, ra.Len(), rb.Len())
		}
		for i := 0; i < ra.Len(); i++ {
			if d := firstDiff(ra.Index(i).Interface(), rb.Index(i).Interface(), fmt.Sprintf("%s[%d]", path, i)); d != "" {
				return d
			}
		}
		return ""
	}
	if !reflect.DeepEqual(a, b) {
		return fmt.Sprintf("%s: %T(%v) from yaml, %T(%v) from hcl", path, a, a, b, b)
	}
	return ""
}

// numericKind reports whether a value is one of Go's numbers, for the
// render-equal comparison above.
func numericKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}
