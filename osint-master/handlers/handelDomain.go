package handlers

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type SubdomainInfo struct {
	Subdomain string
	IPs       []string
	CNAME     string
	HasSSL    bool
	SSLExpiry string
	Risk      string 
	RiskNote  string
}
  

func getSubdomainList() []string {
	return []string{
		
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
		"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
		"ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
		"mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
		"docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
		"web", "media", "email", "images", "img", "download", "dns", "stats",
		"dashboard", "portal", "manage", "start", "info", "apps", "video", "sip",
		"dns2", "api", "cdn", "remote", "server", "stage", "vps", "monitor", "help",
		"git", "jenkins", "jira", "confluence", "bitbucket", "gitlab", "svn",
		"staging", "test", "uat", "qa", "dev-api", "staging-api", "sandbox",
		"security", "vpn", "ssl", "pki", "certs", "auth", "login", "sso", "oauth",
		"cloud", "aws", "azure", "gcp", "s3", "bucket", "storage", "cdn",
		"db", "mysql", "postgres", "mongo", "redis", "elastic", "couchdb",
		"grafana", "prometheus", "kibana", "log", "monitor", "status", "health",
		"sales", "marketing", "hr", "finance", "legal", "careers", "jobs", "press","v1","v2","v0",
	}
}

// Check if subdomain exists and get its IPs
func resolveSubdomain(subdomain string) ([]string, error) {

	/*

	func LookupHost(host string) (addrs []string, err error) {
		return DefaultResolver.LookupHost(context.Background(), host)
	}

	*/
	
	ips, err := net.LookupHost(subdomain)
	if err != nil {
		return nil, err
	}
	fmt.Println("ips =========> ", ips)
	return ips, nil



}

// Get CNAME record for subdomain
func getCNAME(subdomain string) string {
	cname, err := net.LookupCNAME(subdomain)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(cname, ".")
}

// Quick check for SSL certificate (basic version)
func checkSSL(subdomain string) (hasSSL bool, expiry string) {
	// This is a simplified check - for full SSL details you'd need more complex code
	// For now, we'll just indicate if SSL exists
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", subdomain), 2*time.Second)
	if err != nil {
		return false, "No SSL certificate"
	}
	conn.Close()
	return true, "Valid SSL certificate (basic check)"
}




// Analyze subdomain takeover risk
func analyzeTakeoverRisk(subdomain, cname string, ips []string) (risk string, note string) {
	// High risk patterns - CNAME points to external service
	
	if cname != "" {
		cnameLower := strings.ToLower(cname)

		// AWS S3 Bucket takeover
		if strings.Contains(cnameLower, ".s3.amazonaws.com") ||
			strings.Contains(cnameLower, ".s3.") {
			return "HIGH", "CNAME points to AWS S3 bucket - potential takeover if bucket doesn't exist"
		}

		// GitHub Pages takeover
		if strings.Contains(cnameLower, ".github.io") {
			return "HIGH", "CNAME points to GitHub Pages - potential takeover if repository doesn't exist"
		}

		// Heroku takeover
		if strings.Contains(cnameLower, ".herokuapp.com") {
			return "HIGH", "CNAME points to Heroku - potential takeover if app doesn't exist"
		}

		// Azure Web Apps takeover
		if strings.Contains(cnameLower, ".azurewebsites.net") ||
			strings.Contains(cnameLower, ".cloudapp.net") {
			return "HIGH", "CNAME points to Azure - potential takeover if app doesn't exist"
		}

		// Shopify takeover
		if strings.Contains(cnameLower, ".myshopify.com") {
			return "HIGH", "CNAME points to Shopify - potential takeover if store doesn't exist"
		}

		// Medium takeover
		if strings.Contains(cnameLower, ".medium.com") {
			return "HIGH", "CNAME points to Medium - potential takeover if publication doesn't exist"
		}

		// ReadMe.io takeover
		if strings.Contains(cnameLower, ".readme.io") {
			return "HIGH", "CNAME points to ReadMe.io - potential takeover if project doesn't exist"
		}

		// Medium risk - external CNAME but not obviously risky
		return "MEDIUM", fmt.Sprintf("CNAME points to external service: %s", cname)
	}

	// Low risk patterns - direct A/AAAA records
	if len(ips) > 0 {
		return "LOW", "Direct IP mapping - takeover unlikely"
	}

	return "UNKNOWN", "No DNS records found"
}

// HandleDomain is the main function for domain enumeration
func HandleDomain(domain string) string {
	output := fmt.Sprintf("Main Domain: %s\n", domain)
	output += strings.Repeat("=", 70) + "\n\n"

	output += "[INFO] Enumerating subdomains...\n"
	output += "[INFO] This may take a few moments\n\n"

	subdomainsList := getSubdomainList()
	var foundSubdomains []SubdomainInfo
	checkedCount := 0

	output += " CHECKING SUBDOMAINS:\n"
	output += strings.Repeat("-", 70) + "\n"

	for _, sub := range subdomainsList {
		subdomain := fmt.Sprintf("%s.%s", sub, domain)
		checkedCount++

		// Try to resolve the subdomain
		ips, err := resolveSubdomain(subdomain)
		if err == nil && len(ips) > 0 {
			// Subdomain exists!
			cname := getCNAME(subdomain)
			hasSSL, sslExpiry := checkSSL(subdomain)
			risk, riskNote := analyzeTakeoverRisk(subdomain, cname, ips)

			info := SubdomainInfo{
				Subdomain: subdomain,
				IPs:       ips,
				CNAME:     cname,
				HasSSL:    hasSSL,
				SSLExpiry: sslExpiry,
				Risk:      risk,
				RiskNote:  riskNote,
			}
			foundSubdomains = append(foundSubdomains, info)

			// Display found subdomain
			output += fmt.Sprintf("\n✓ %s\n", subdomain)
			output += fmt.Sprintf("    IP Addresses: %s\n", strings.Join(ips, ", "))
			if cname != "" {
				output += fmt.Sprintf("    CNAME Record: %s\n", cname)
			}
			output += fmt.Sprintf("    SSL: %s\n", sslExpiry)
			output += fmt.Sprintf("      Risk: %s - %s\n", risk, riskNote)
		}

		// Show progress every 50 checks
		if checkedCount%50 == 0 {
			output += fmt.Sprintf("\n[PROGRESS] Checked %d/%d subdomains...\n", checkedCount, len(subdomainsList))
		}
	}

	// Summary section
	output += "\n" + strings.Repeat("=", 70) + "\n"
	output += "ENUMERATION SUMMARY:\n"
	output += strings.Repeat("-", 70) + "\n"
	output += fmt.Sprintf("  Total subdomains checked: %d\n", checkedCount)
	output += fmt.Sprintf("  Active subdomains found: %d\n", len(foundSubdomains))

	if len(foundSubdomains) > 0 {
		output += "\n HIGH RISK SUBDOMAINS (Check for takeover):\n"
		highRiskFound := false
		for _, sub := range foundSubdomains {
			if sub.Risk == "HIGH" {
				highRiskFound = true
				output += fmt.Sprintf("  - %s\n", sub.Subdomain)
				output += fmt.Sprintf("    ➜ %s\n", sub.RiskNote)
			}
		}
		if !highRiskFound {
			output += "  No high-risk subdomains detected\n"
		}

		output += "\n ALL ACTIVE SUBDOMAINS:\n"
		for i, sub := range foundSubdomains {
			riskIndicator := "-"
			if sub.Risk == "HIGH" {
				riskIndicator = "*"
			} else if sub.Risk == "MEDIUM" {
				riskIndicator = "+"
			}
			output += fmt.Sprintf("  %d. %s %s\n", i+1, riskIndicator, sub.Subdomain)
		}
	}

	// OSINT Tips
	output += "\n" + strings.Repeat("=", 70) + "\n"
	output += " OSINT & RECOMMENDATIONS:\n"
	output += strings.Repeat("-", 70) + "\n"
	output += "  1. For HIGH risk subdomains, verify if the external service still exists\n"
	output += "  2. Remove DNS records pointing to services you no longer use\n"
	output += "  3. Use tools like 'dig', 'nslookup' for deeper investigation\n"
	output += "  4. Check Certificate Transparency logs (crt.sh) for more subdomains\n"
	output += "  5. Consider using Sublist3r, Amass, or Subfinder for comprehensive scans\n"

	output += "\n	USEFUL RESOURCES:\n"
	output += fmt.Sprintf("  - SecurityTrails: https://securitytrails.com/domain/%s\n", domain)
	output += fmt.Sprintf("  - crt.sh: https://crt.sh/?q=%%.%s\n", domain)
	output += fmt.Sprintf("  - DNSDumpster: https://dnsdumpster.com/domain/%s\n", domain)

	output += "\n LEGAL NOTE:\n"
	output += "  Only scan domains you own or have explicit permission to test.\n"
	output += "  Unauthorized scanning may violate laws and terms of service.\n"

	return output
}
