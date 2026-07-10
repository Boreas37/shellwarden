package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// vulnScan is the result of a host vulnerability scan.
type vulnScan struct {
	Tool            string        `json:"tool"`
	Distro          string        `json:"distro"`
	Upgradable      int           `json:"upgradable"`
	SecurityUpdates int           `json:"security_updates"`
	Findings        []vulnFinding `json:"findings"`
	ScannedAt       string        `json:"scanned_at"`
	Note            string        `json:"note,omitempty"`
}

type vulnFinding struct {
	ID       string `json:"id"` // CVE / advisory id (or package)
	Package  string `json:"package"`
	Severity string `json:"severity"` // critical | high | medium | low | unknown
}

const vulnScanTick = 6 * time.Hour

// runVulnScan periodically scans the host for known vulnerabilities, using each
// distro's native security tooling.
func runVulnScan(send func([]byte)) {
	if _, err := os.Stat("/etc/os-release"); err != nil {
		return // not a Linux host
	}
	emit := func() {
		s := scanHost()
		if b, err := json.Marshal(s); err == nil {
			send(b)
		}
	}
	time.Sleep(20 * time.Second) // let the agent settle / network come up
	emit()
	ticker := time.NewTicker(vulnScanTick)
	defer ticker.Stop()
	for range ticker.C {
		emit()
	}
}

func scanHost() vulnScan {
	s := vulnScan{ScannedAt: time.Now().UTC().Format(time.RFC3339), Findings: []vulnFinding{}}
	id, like := osID()
	switch {
	case contains(id, like, "debian", "ubuntu"):
		s.Distro = "debian"
		scanDebian(&s)
	case contains(id, like, "rhel", "centos", "fedora", "rocky", "almalinux"):
		s.Distro = "rhel"
		scanRHEL(&s)
	case contains(id, like, "arch"):
		s.Distro = "arch"
		scanArch(&s)
	default:
		s.Distro = id
		s.Note = "no vulnerability scanner for this distro"
	}
	log.Printf("vuln scan: distro=%s tool=%s upgradable=%d security=%d findings=%d",
		s.Distro, s.Tool, s.Upgradable, s.SecurityUpdates, len(s.Findings))
	return s
}

// --- Debian / Ubuntu ---
func scanDebian(s *vulnScan) {
	// Refresh package lists (best-effort, short timeout).
	_, _ = run(60*time.Second, "apt-get", "update", "-qq")

	// Upgradable packages + security count.
	if out, err := run(30*time.Second, "apt-get", "-s", "upgrade"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Inst ") {
				s.Upgradable++
				if strings.Contains(strings.ToLower(line), "security") {
					s.SecurityUpdates++
				}
			}
		}
	}

	// Real CVE mapping via debsecan, if present. Default format is:
	//   CVE-2016-2781 coreutils (low urgency)
	if hasCmd("debsecan") {
		s.Tool = "debsecan"
		if out, err := run(120*time.Second, "debsecan"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && strings.HasPrefix(f[0], "CVE-") {
					sev := "unknown"
					if i := strings.Index(line, "urgency"); i > 0 {
						sev = normSeverity(line[:i])
					}
					s.Findings = append(s.Findings, vulnFinding{ID: f[0], Package: f[1], Severity: sev})
				}
			}
		}
		return
	}
	s.Tool = "apt"
	s.Note = "install 'debsecan' for CVE-level detail"
}

// --- RHEL family (dnf updateinfo gives native CVE + severity) ---
func scanRHEL(s *vulnScan) {
	s.Tool = "dnf"
	mgr := "dnf"
	if !hasCmd("dnf") {
		mgr = "yum"
		s.Tool = "yum"
	}
	if out, err := run(120*time.Second, mgr, "-q", "updateinfo", "list", "security"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 3 {
				continue
			}
			s.SecurityUpdates++
			s.Findings = append(s.Findings, vulnFinding{
				ID: f[0], Package: f[len(f)-1], Severity: normSeverity(f[1]),
			})
		}
	}
}

// --- Arch (arch-audit maps to CVEs + severity) ---
func scanArch(s *vulnScan) {
	if u, err := run(20*time.Second, "pacman", "-Qu"); err == nil {
		s.Upgradable = countLines(u)
	}
	if hasCmd("arch-audit") {
		s.Tool = "arch-audit"
		if out, err := run(60*time.Second, "arch-audit", "-uf", "%n|%c|%s"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				p := strings.Split(line, "|")
				if len(p) >= 3 {
					s.SecurityUpdates++
					s.Findings = append(s.Findings, vulnFinding{
						ID: p[1], Package: p[0], Severity: normSeverity(p[2]),
					})
				}
			}
		}
		return
	}
	s.Tool = "pacman"
	s.Note = "install 'arch-audit' for CVE-level detail"
}

// --- helpers ---
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func osID() (id, like string) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		v := strings.Trim(strings.TrimPrefix(line, strings.SplitN(line, "=", 2)[0]+"="), `"`)
		switch {
		case strings.HasPrefix(line, "ID="):
			id = v
		case strings.HasPrefix(line, "ID_LIKE="):
			like = v
		}
	}
	return id, like
}

func contains(id, like string, names ...string) bool {
	hay := id + " " + like
	for _, n := range names {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(s, "critical"):
		return "critical"
	case strings.Contains(s, "important"), strings.Contains(s, "high"):
		return "high"
	case strings.Contains(s, "moderate"), strings.Contains(s, "medium"):
		return "medium"
	case strings.Contains(s, "low"):
		return "low"
	default:
		return "unknown"
	}
}

func countLines(s string) int {
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}
