package cjson

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalAppliesRFC8785Canonicalization(t *testing.T) {
	value := map[string]any{
		"numbers": []any{
			333333333.33333329,
			json.Number("1E30"),
			json.Number("4.50"),
			json.Number("2e-3"),
			json.Number("0.000000000000000000000000001"),
		},
		"string":   "\u20ac$\u000f\nA'B\"\\\\\"/",
		"literals": []any{nil, true, false},
	}

	raw, err := Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	expected := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	if string(raw) != expected {
		t.Fatalf("Marshal() = %s, want %s", string(raw), expected)
	}
}

func TestMarshalDoesNotHTMLEscapeStrings(t *testing.T) {
	value := map[string]any{
		"body": map[string]any{
			"text": "alice->group <hello> & goodbye",
		},
		"meta": map[string]any{
			"a": "b",
		},
		"method": "group.send",
	}

	raw, err := Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if bytes.Contains(raw, []byte(`\u003c`)) || bytes.Contains(raw, []byte(`\u003e`)) || bytes.Contains(raw, []byte(`\u0026`)) {
		t.Fatalf("Marshal() unexpectedly HTML-escaped string content: %s", string(raw))
	}
	if !bytes.Contains(raw, []byte(`alice->group <hello> & goodbye`)) {
		t.Fatalf("Marshal() missing literal string content: %s", string(raw))
	}
}

func TestMarshalSortsKeysByUTF16CodeUnits(t *testing.T) {
	value := map[string]any{
		"\u20ac":     "euro",
		"\r":         "cr",
		"\ufb33":     "hebrew",
		"1":          "digit",
		"\U0001f600": "emoji",
		"\u0080":     "control",
		"\u00f6":     "oumlaut",
	}

	raw, err := Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	expected := "{\"\\r\":\"cr\",\"1\":\"digit\",\"\u0080\":\"control\",\"\u00f6\":\"oumlaut\",\"\u20ac\":\"euro\",\"\U0001f600\":\"emoji\",\"\ufb33\":\"hebrew\"}"
	if string(raw) != expected {
		t.Fatalf("Marshal() = %q, want %q", string(raw), expected)
	}
}
