// Package cve enriches CVE identifiers with a CVSS-based severity by querying
// the public OSV.dev database. Results are cached in memory so repeated scans
// across hosts are cheap.
package cve

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	mu     sync.Mutex
	cache  = map[string]string{} // CVE -> severity (incl. "" when looked up but unknown)
	client = &http.Client{Timeout: 8 * time.Second}
)

// Enrich returns a CVE -> severity map for the given ids (critical/high/medium/
// low, or "" when no CVSS is available). Lookups run concurrently and cached.
func Enrich(ids []string) map[string]string {
	out := make(map[string]string, len(ids))

	// Split cached vs. to-fetch.
	var todo []string
	mu.Lock()
	for _, id := range ids {
		if v, ok := cache[id]; ok {
			out[id] = v
		} else {
			todo = append(todo, id)
		}
	}
	mu.Unlock()

	if len(todo) == 0 {
		return out
	}

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	results := make([]string, len(todo))
	for i, id := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, id string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = fetchSeverity(id)
		}(i, id)
	}
	wg.Wait()

	mu.Lock()
	for i, id := range todo {
		cache[id] = results[i]
		out[id] = results[i]
	}
	mu.Unlock()
	return out
}

// fetchSeverity queries OSV for a CVE and returns the highest CVSS severity.
func fetchSeverity(cve string) string {
	if !strings.HasPrefix(cve, "CVE-") {
		return ""
	}
	resp, err := client.Get("https://api.osv.dev/v1/vulns/" + cve)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var body struct {
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return ""
	}

	best := 0.0
	for _, s := range body.Severity {
		var score float64
		switch {
		case strings.HasPrefix(s.Score, "CVSS:3"):
			score = cvssV3Score(s.Score)
		case strings.Contains(s.Score, "AV:") && strings.Contains(s.Score, "Au:"):
			score = cvssV2Score(s.Score)
		}
		if score > best {
			best = score
		}
	}
	return bucket(best)
}

func bucket(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

func parseVector(v string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(v, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

func roundup(x float64) float64 { return math.Ceil(x*10) / 10 }

// cvssV3Score computes a CVSS v3.0/3.1 base score from a vector string.
func cvssV3Score(vec string) float64 {
	m := parseVector(vec)
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	scopeChanged := m["S"] == "C"
	var pr float64
	if scopeChanged {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	} else {
		pr = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	expl := 8.22 * av * ac * pr * ui
	if scopeChanged {
		return roundup(math.Min(1.08*(impact+expl), 10))
	}
	return roundup(math.Min(impact+expl, 10))
}

// cvssV2Score computes a CVSS v2 base score from a vector string.
func cvssV2Score(vec string) float64 {
	m := parseVector(vec)
	av := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]]
	ac := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]]
	au := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}[m["Au"]]
	cia := map[string]float64{"N": 0.0, "P": 0.275, "C": 0.660}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]

	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	expl := 20 * av * ac * au
	f := 1.176
	if impact == 0 {
		f = 0
	}
	score := (0.6*impact + 0.4*expl - 1.5) * f
	return math.Round(score*10) / 10
}
