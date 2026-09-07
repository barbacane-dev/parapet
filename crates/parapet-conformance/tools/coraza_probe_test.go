package transformations

// Emits reference outputs for a corpus of (transformation, input) pairs so an
// independent implementation can be differential-tested against Coraza.
// Inputs and outputs are hex-encoded so binary survives the round trip.
import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type probeCase struct {
	Name  string `json:"name"`
	Input string `json:"input"`
}

type probeResult struct {
	Name   string `json:"name"`
	Input  string `json:"input"`
	Output string `json:"output"`
	Err    string `json:"err,omitempty"`
}

func TestParapetProbe(t *testing.T) {
	inPath := os.Getenv("PROBE_IN")
	outPath := os.Getenv("PROBE_OUT")
	if inPath == "" || outPath == "" {
		t.Skip("PROBE_IN/PROBE_OUT not set")
	}
	raw, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatal(err)
	}
	var cases []probeCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	results := make([]probeResult, 0, len(cases))
	for _, c := range cases {
		inBytes, err := hex.DecodeString(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		fn, err := GetTransformation(c.Name)
		if err != nil {
			results = append(results, probeResult{Name: c.Name, Input: c.Input, Err: err.Error()})
			continue
		}
		out, _, err := fn(string(inBytes))
		r := probeResult{Name: c.Name, Input: c.Input, Output: hex.EncodeToString([]byte(out))}
		if err != nil {
			r.Err = err.Error()
		}
		results = append(results, r)
	}
	enc, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, enc, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d reference results", len(results))
}
