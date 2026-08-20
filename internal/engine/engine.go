package engine

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
)

const (
	versionMissingPenalty = 0.2
	productMissingPenalty = 0.2
)

type Extractor struct {
	Re  string `json:"re"`
	Tpl string `json:"tpl"`
}

type Rule struct {
	ID         string    `json:"id"`
	Protocol   string    `json:"protocol"`
	Priority   int       `json:"priority"`
	Match      string    `json:"match"`
	Product    Extractor `json:"product"`
	Version    Extractor `json:"version"`
	OS         Extractor `json:"os"`
	Confidence float64   `json:"confidence"`
}

type compiledExtractor struct {
	re  *regexp.Regexp
	tpl string
}

type compiledRule struct {
	rule    Rule
	match   *regexp.Regexp
	product compiledExtractor
	version compiledExtractor
	os      compiledExtractor
}

type Engine struct {
	rules []compiledRule
}

type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

func LoadFromFile(path string) (*Engine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

func Load(r io.Reader) (*Engine, error) {
	var rules []Rule
	if err := json.NewDecoder(r).Decode(&rules); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, errors.New("no fingerprint rules loaded")
	}

	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		cr, err := compileRule(rule)
		if err != nil {
			continue
		}
		compiled = append(compiled, cr)
	}
	if len(compiled) == 0 {
		return nil, errors.New("no valid fingerprint rules loaded")
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		return compiled[i].rule.Priority > compiled[j].rule.Priority
	})

	return &Engine{rules: compiled}, nil
}

func (e *Engine) Ready() bool {
	return e != nil && len(e.rules) > 0
}

func (e *Engine) Fingerprint(in Input) (out Result) {
	out = unknownResult(in)
	defer func() {
		if recover() != nil {
			out = unknownResult(in)
		}
	}()

	if e == nil {
		return out
	}

	banner := []byte(in.Banner)
	for _, cr := range e.rules {
		if !cr.match.Match(banner) {
			continue
		}

		out.Protocol = cr.rule.Protocol
		out.Product = extract(cr.product, banner)
		out.Version = extract(cr.version, banner)
		out.OSHint = extract(cr.os, banner)
		out.Confidence = score(cr.rule.Confidence, out.Product, out.Version)
		return out
	}

	return out
}

func compileRule(rule Rule) (compiledRule, error) {
	match, err := regexp.Compile(rule.Match)
	if err != nil {
		return compiledRule{}, err
	}

	product, err := compileExtractor(rule.Product)
	if err != nil {
		return compiledRule{}, err
	}
	version, err := compileExtractor(rule.Version)
	if err != nil {
		return compiledRule{}, err
	}
	os, err := compileExtractor(rule.OS)
	if err != nil {
		return compiledRule{}, err
	}

	return compiledRule{
		rule:    rule,
		match:   match,
		product: product,
		version: version,
		os:      os,
	}, nil
}

func compileExtractor(ex Extractor) (compiledExtractor, error) {
	if ex.Re == "" {
		return compiledExtractor{tpl: ex.Tpl}, nil
	}
	re, err := regexp.Compile(ex.Re)
	if err != nil {
		return compiledExtractor{}, err
	}
	return compiledExtractor{re: re, tpl: ex.Tpl}, nil
}

func extract(ex compiledExtractor, banner []byte) string {
	if ex.re == nil {
		return ""
	}
	idx := ex.re.FindSubmatchIndex(banner)
	if idx == nil {
		return ""
	}
	return string(ex.re.Expand(nil, []byte(ex.tpl), banner, idx))
}

func score(base float64, product, version string) float64 {
	if product == "" {
		base -= productMissingPenalty
	}
	if version == "" {
		base -= versionMissingPenalty
	}
	if base < 0 {
		return 0
	}
	if base > 1 {
		return 1
	}
	return base
}

func unknownResult(in Input) Result {
	return Result{
		IP:       in.IP,
		Port:     in.Port,
		Protocol: "unknown",
	}
}
