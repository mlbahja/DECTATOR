package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/PuerkitoBio/goquery"
)

type ContactInfo struct {
	Phone   string
	Address string
	City    string
	State   string
}

func IsAllAlpha(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}


// scrapeUSPhoneBookWithProxy attempts to scrape with an optional proxy
func scrapeUSPhoneBookWithProxy(firstName, lastName, proxyAddress string) ([]ContactInfo, error) {
	// Build search URL
	searchURL := fmt.Sprintf("https://www.usphonebook.com/search?first=%s&last=%s",
		url.QueryEscape(firstName), url.QueryEscape(lastName))

	// Create HTTP client
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// Add proxy if provided
	if proxyAddress != "" {
		proxyURL, err := url.Parse(proxyAddress)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}
		}
	}

	// Create request
	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		return nil, err
	}

	// Set realistic browser headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP error: %d (blocked by anti-bot protection)", resp.StatusCode)
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	var contacts []ContactInfo

	// Try different CSS selectors that USPhoneBook might use
	selectors := []string{
		".search-result",
		".result-item",
		".person-result",
		".listing-card",
		"div[data-testid='result']",
	}

	for _, selector := range selectors {
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			contact := ContactInfo{}

			// Try different phone selectors
			phoneSelectors := []string{".phone", ".phone-num", "a[href^='tel:']", ".number", "[data-phone]"}
			for _, phoneSel := range phoneSelectors {
				if phone := s.Find(phoneSel).Text(); phone != "" {
					contact.Phone = strings.TrimSpace(phone)
					break
				}
			}

			// Try different address selectors
			addressSelectors := []string{".address", ".street-address", ".address-line", ".location", ".adr"}
			for _, addrSel := range addressSelectors {
				if address := s.Find(addrSel).Text(); address != "" {
					contact.Address = strings.TrimSpace(address)
					break
				}
			}

			if contact.Phone != "" || contact.Address != "" {
				contacts = append(contacts, contact)
			}
		})

		if len(contacts) > 0 {
			break
		}
	}

	return contacts, nil
}

// HandleNameScraper is the main function that attempts scraping with fallback
func HandleNameScraper(fullName string) string {
	parts := strings.Fields(fullName)
	if len(parts) < 2 {
		return "Error: Please provide both first and last name\n"
	}

	firstName := parts[0]
	lastName := strings.Join(parts[1:], " ")

	// Validate names contain only letters
	if !IsAllAlpha(firstName) || !IsAllAlpha(lastName) {
		return "Error: Name should contain only letters\n"
	}

	output := fmt.Sprintf("First name: %s\n", firstName)
	output += fmt.Sprintf("Last name: %s\n\n", lastName)

	output += "[INFO] Attempting to scrape USPhoneBook.com...\n"
	output += "[INFO] This may be blocked by anti-bot protection\n\n"

	// Try without proxy first
	contacts, err := scrapeUSPhoneBookWithProxy(firstName, lastName, "")

	if err != nil && strings.Contains(err.Error(), "403") {
		output += "[WARNING] Direct access blocked (403 error)\n"
		output += "[INFO] Trying with proxy... (You need to configure a real proxy)\n\n"
	}

	if err != nil {
		output += fmt.Sprintf("[ERROR] Scraping failed: %v\n\n", err)
		output += getManualSearchLinks(firstName, lastName)
		return output
	}

	if len(contacts) == 0 {
		output += "[INFO] No results found on USPhoneBook\n\n"
		output += getManualSearchLinks(firstName, lastName)
	} else {
		output += fmt.Sprintf("[SUCCESS] Found %d result(s):\n\n", len(contacts))
		for i, contact := range contacts {
			output += fmt.Sprintf("Result #%d:\n", i+1)
			if contact.Phone != "" {
				output += fmt.Sprintf("  Phone: %s\n", contact.Phone)
			}
			if contact.Address != "" {
				output += fmt.Sprintf("  Address: %s\n", contact.Address)
			}
			output += "\n"
		}
	}

	return output
}

// getManualSearchLinks provides alternative search methods when scraping fails
func getManualSearchLinks(firstName, lastName string) string {
	output := "MANUAL OSINT SEARCH LINKS:\n"
	output += "================================\n\n"

	output += "PHONE NUMBER DIRECTORIES:\n"
	output += fmt.Sprintf("  - USPhoneBook: https://www.usphonebook.com/search?first=%s&last=%s\n",
		url.QueryEscape(firstName), url.QueryEscape(lastName))
	output += fmt.Sprintf("  - Whitepages: https://www.whitepages.com/name/%s-%s\n",
		firstName, lastName)
	output += fmt.Sprintf("  - AnyWho: https://www.anywho.com/people/%s/%s\n",
		firstName, lastName)
	output += fmt.Sprintf("  - ZabaSearch: https://www.zabasearch.com/people/%s+%s/\n",
		firstName, lastName)
	output += fmt.Sprintf("  - TruePeopleSearch: https://www.truepeoplesearch.com/results?name=%s+%s\n",
		firstName, lastName)

	output += "\nSOCIAL MEDIA SEARCH:\n"
	output += fmt.Sprintf("  - LinkedIn: https://www.linkedin.com/search/results/people/?keywords=%s+%s\n",
		firstName, lastName)
	output += fmt.Sprintf("  - Facebook: https://www.facebook.com/search/people/?q=%s+%s\n",
		firstName, lastName)
	output += fmt.Sprintf("  - Twitter/X: https://twitter.com/search?q=%s+%s\n",
		firstName, lastName)
	output += fmt.Sprintf("  - Instagram: https://www.instagram.com/web/search/top/?q=%s+%s\n",
		firstName, lastName)
	output += fmt.Sprintf("  - GitHub: https://github.com/search?q=%s+%s&type=users\n",
		firstName, lastName)

	output += "\nEMAIL PATTERN GUESSING:\n"
	lowerFirst := strings.ToLower(firstName)
	lowerLast := strings.ToLower(lastName)
	output += fmt.Sprintf("  - %s.%s@gmail.com\n", lowerFirst, lowerLast)
	output += fmt.Sprintf("  - %s%s@gmail.com\n", lowerFirst, lowerLast)
	output += fmt.Sprintf("  - %s.%s@outlook.com\n", lowerFirst, lowerLast)
	output += fmt.Sprintf("  - %s@%s.com (if domain known)\n", lowerFirst, lowerLast)

	output += "\nGOOGLE DORKS (Advanced Search):\n"
	output += fmt.Sprintf("  - site:linkedin.com/in \"%s %s\"\n", firstName, lastName)
	output += fmt.Sprintf("  - \"%s %s\" phone number\n", firstName, lastName)
	output += fmt.Sprintf("  - intitle:\"%s\" intitle:\"%s\"\n", firstName, lastName)

	output += "\nPROFESSIONAL API SOLUTION:\n"
	output += "  For automated data retrieval, use People Data Labs API:\n"
	output += "  - Sign up: https://www.peopledatalabs.com/\n"
	output += "  - Free tier: 100 requests/month\n"
	output += "  - Returns: phone, email, address, social profiles\n"

	output += "\nLEGAL AND ETHICAL NOTE:\n"
	output += "  - Always obtain consent before gathering personal information\n"
	output += "  - Respect privacy laws (GDPR, CCPA)\n"
	output += "  - Use this tool for educational purposes only\n"

	return output   
	
}