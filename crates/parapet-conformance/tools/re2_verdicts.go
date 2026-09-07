package main

// Verdicts for the ORIGINAL CRS patterns under Go/RE2, the engine Coraza uses.
import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type pat struct {
	ID       string `json:"id"`
	Original string `json:"original"`
	Repaired string `json:"repaired"`
}
type input struct {
	Patterns []pat               `json:"patterns"`
	Corpus   map[string][]string `json:"corpus"`
}

func main() {
	b, _ := os.ReadFile(os.Args[1])
	var in input
	if err := json.Unmarshal(b, &in); err != nil {
		panic(err)
	}
	res := map[string][]bool{}
	for _, p := range in.Patterns {
		re, err := regexp.Compile(p.Original)
		if err != nil {
			panic(fmt.Sprintf("RE2 rejected %s: %v", p.ID, err))
		}
		v := make([]bool, len(in.Corpus[p.ID]))
		for i, s := range in.Corpus[p.ID] {
			v[i] = re.MatchString(s)
		}
		res[p.ID] = v
	}
	o, _ := json.Marshal(res)
	os.WriteFile(os.Args[2], o, 0o644)
	fmt.Println("RE2 verdicts written for", len(res), "patterns")
}
