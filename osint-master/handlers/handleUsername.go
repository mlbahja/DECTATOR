package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"osint-master/help"
	"strings"
	"time"
)

type Platform struct {
	Name     string
	URL      string
	Category string
}

func GetPlatforms() []Platform {
	return []Platform{
		{Name: "GitHub", URL: "https://github.com/%s", Category: "Development"},
		{Name: "Twitter", URL: "https://twitter.com/%s", Category: "Social"},
		{Name: "Instagram", URL: "https://instagram.com/%s", Category: "Social"},
		{Name: "Reddit", URL: "https://reddit.com/user/%s", Category: "Social"},
		{Name: "LinkedIn", URL: "https://linkedin.com/in/%s", Category: "Professional"},
		{Name: "Medium", URL: "https://medium.com/@%s", Category: "Blogging"},
		{Name: "GitLab", URL: "https://gitlab.com/%s", Category: "Development"},
		{Name: "Pinterest", URL: "https://pinterest.com/%s", Category: "Social"},
	}
}

// ProfileInfo holds the enriched data pulled from platforms that expose a public API.
// Left empty (zero value) for platforms we can't safely enrich (Instagram, LinkedIn, etc).
type ProfileInfo struct {
	Bio          string
	Followers    int
	ActivityInfo string // e.g. "last active 2 days ago" or "142 public repos"
	Enriched     bool   // true if we actually managed to pull extra data
}

type CheckResult struct {
	Platform string
	URL      string
	Username string
	Found    bool
	Category string
	Profile  ProfileInfo
}

// ---------- Presence check ----------

func checkUsernameOnPlatform(username string, platform Platform, client *http.Client) CheckResult {
	url := fmt.Sprintf(platform.URL, username)

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return CheckResult{Platform: platform.Name, URL: url, Username: username, Found: false, Category: platform.Category}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return CheckResult{Platform: platform.Name, URL: url, Username: username, Found: false, Category: platform.Category}
	}
	defer resp.Body.Close()

	found := resp.StatusCode == 200 || resp.StatusCode == 302

	result := CheckResult{
		Platform: platform.Name,
		URL:      url,
		Username: username,
		Found:    found,
		Category: platform.Category,
	}

	// Only bother enriching platforms we actually found, and only ones with a
	// reliable public API. Everything else stays Found/Not Found only.
	if found {
		switch platform.Name {
		case "GitHub":
			if profile := enrichGitHub(username, client); profile != nil {
				result.Profile = *profile
			}
		case "Reddit":
			if profile := enrichReddit(username, client); profile != nil {
				result.Profile = *profile
			}
		}
	}

	return result
}

// ---------- GitHub enrichment ----------

type githubAPIResponse struct {
	Bio         string `json:"bio"`
	Followers   int    `json:"followers"`
	PublicRepos int    `json:"public_repos"`
	CreatedAt   string `json:"created_at"`
}

func enrichGitHub(username string, client *http.Client) *ProfileInfo {
	url := fmt.Sprintf("https://api.github.com/users/%s", username)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "osint-master")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil // rate-limited (403) or user not found (404) — fail quietly
	}

	var data githubAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	bio := data.Bio
	if bio == "" {
		bio = "N/A"
	}

	return &ProfileInfo{
		Bio:          bio,
		Followers:    data.Followers,
		ActivityInfo: fmt.Sprintf("%d public repos", data.PublicRepos),
		Enriched:     true,
	}
	
}

// ---------- Reddit enrichment ----------

type redditAPIResponse struct {
	Data struct {
		Subreddit struct {
			PublicDescription string `json:"public_description"`
		} `json:"subreddit"`
		CommentKarma float64 `json:"comment_karma"`
		LinkKarma    float64 `json:"link_karma"`
		CreatedUTC   float64 `json:"created_utc"`
	} `json:"data"`
}

func enrichReddit(username string, client *http.Client) *ProfileInfo {
	url := fmt.Sprintf("https://www.reddit.com/user/%s/about.json", username)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	// Reddit blocks generic/default user-agents aggressively — be specific.
	req.Header.Set("User-Agent", "osint-master/1.0 (educational OSINT tool)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	var data redditAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	bio := data.Data.Subreddit.PublicDescription
	if bio == "" {
		bio = "N/A"
	}

	totalKarma := int(data.Data.CommentKarma + data.Data.LinkKarma)

	return &ProfileInfo{
		Bio:          bio,
		Followers:    0, // Reddit doesn't expose follower count publicly
		ActivityInfo: fmt.Sprintf("%d total karma", totalKarma),
		Enriched:     true,
	}
}

// ---------- Output formatting ----------

func formatResult(result CheckResult) string {
	line := fmt.Sprintf("[FOUND] %s: %s\n", result.Platform, result.URL)

	if result.Profile.Enriched {
		line += fmt.Sprintf("    Bio: %s\n", result.Profile.Bio)
		if result.Profile.Followers > 0 {
			line += fmt.Sprintf("    Followers: %d\n", result.Profile.Followers)
		}
		line += fmt.Sprintf("    Activity: %s\n", result.Profile.ActivityInfo)
	}

	return line
}

// ---------- Handlers ----------

// HandleUsername checks if a username exists on platforms and enriches
// results for platforms with a reliable public API (GitHub, Reddit).
func HandleUsername(username string) string {
	username = strings.TrimPrefix(username, "@")

	if username == "" {
		return "Error: Please provide a valid username\n"
	}

	output := fmt.Sprintf("Checking username: %s\n", username)
	output += strings.Repeat("=", 50) + "\n\n"

	client := &http.Client{Timeout: 8 * time.Second}

	platforms := GetPlatforms()
	var foundResults []CheckResult

	output += "Searching platforms...\n\n"

	for _, platform := range platforms {
		result := checkUsernameOnPlatform(username, platform, client)
		if result.Found {
			foundResults = append(foundResults, result)
			output += formatResult(result)
		}
	}

	if len(foundResults) == 0 {
		output += "\nNo profiles found for this username\n"
	}

	output += "\n" + strings.Repeat("=", 50) + "\n"
	output += fmt.Sprintf("Total profiles found: %d/%d\n", len(foundResults), len(platforms))

	return output
}

// HandleUsernameFromName generates usernames from a name and checks them.
func HandleUsernameFromName(fullName string) string {
	usernames := help.GenerateFromFullName(fullName)

	if len(usernames) == 0 {
		return "Error: Could not generate usernames from provided name\n"
	}

	output := fmt.Sprintf("Full Name: %s\n", fullName)
	output += fmt.Sprintf("Generated %d possible username variations\n", len(usernames))
	output += strings.Repeat("=", 50) + "\n\n"

	client := &http.Client{Timeout: 5 * time.Second}

	platforms := GetPlatforms()
	allResults := make(map[string][]CheckResult)

	maxUsernames := 20
	if len(usernames) < maxUsernames {
		maxUsernames = len(usernames)
	}

	output += "Checking username variations on platforms...\n\n"

	for i := 0; i < maxUsernames; i++ {
		username := usernames[i]
		var foundForThisUser []CheckResult

		for _, platform := range platforms {
			result := checkUsernameOnPlatform(username, platform, client)
			if result.Found {
				foundForThisUser = append(foundForThisUser, result)
			}
		}

		if len(foundForThisUser) > 0 {
			allResults[username] = foundForThisUser
			output += fmt.Sprintf("\n[VALID USERNAME] %s\n", username)
			for _, result := range foundForThisUser {
				output += formatResult(result)
			}
		}
	}

	if len(allResults) == 0 {
		output += "\nNo valid usernames found from generated variations\n"
		output += "Try a different name or check common patterns manually\n"
	} else {
		output += "\n" + strings.Repeat("=", 50) + "\n"
		output += fmt.Sprintf("Found %d valid username(s) out of %d checked\n", len(allResults), maxUsernames)
	}

	output += "\nOSINT TIPS:\n"
	output += "  - Use the -u flag to check specific usernames\n"
	output += "  - Try common years (1985, 1990) or birth years\n"
	output += "  - Check email addresses derived from these usernames\n"

	return output
}

// HandleGenerateAndTestUsernames generates usernames from a full name and
// tests them, reusing the same enrichment-aware check as HandleUsername.
func HandleGenerateAndTestUsernames(fullName string) string {
	usernames := help.GenerateFromFullName(fullName)

	if len(usernames) == 0 {
		return fmt.Sprintf("Error: Could not generate usernames from '%s'\n", fullName)
	}

	output := fmt.Sprintf("Full Name: %s\n", fullName)
	output += fmt.Sprintf("Generated %d username variations\n", len(usernames))
	output += strings.Repeat("=", 60) + "\n\n"

	maxToCheck := 30
	if len(usernames) < maxToCheck {
		maxToCheck = len(usernames)
	}

	output += fmt.Sprintf("Testing %d most likely username variations on social platforms...\n", maxToCheck)
	output += strings.Repeat("-", 60) + "\n\n"

	client := &http.Client{Timeout: 5 * time.Second}
	platforms := GetPlatforms()

	var validUsernames []string
	validCount := 0

	for i := 0; i < maxToCheck; i++ {
		username := usernames[i]
		var foundOn []string

		// Reuses checkUsernameOnPlatform instead of duplicating the HTTP
		// logic — keeps enrichment behavior consistent everywhere.
		for _, platform := range platforms {
			result := checkUsernameOnPlatform(username, platform, client)
			if result.Found {
				foundOn = append(foundOn, result.Platform)
			}
		}

		if len(foundOn) > 0 {
			validCount++
			validUsernames = append(validUsernames, username)
			output += fmt.Sprintf("\n[VALID] %s - Found on: %s\n", username, strings.Join(foundOn, ", "))
		}
	}

	output += "\n" + strings.Repeat("=", 60) + "\n"
	output += "\nSUMMARY:\n"
	output += fmt.Sprintf("  - Total username variations generated: %d\n", len(usernames))
	output += fmt.Sprintf("  - Usernames tested: %d\n", maxToCheck)
	output += fmt.Sprintf("  - Valid usernames found: %d\n", validCount)

	if validCount > 0 {
		output += "\nVALID USERNAMES TO INVESTIGATE:\n"
		for i, username := range validUsernames {
			if i < 10 {
				output += fmt.Sprintf("  %d. %s\n", i+1, username)
			}
		}
	}

	output += "\n" + strings.Repeat("=", 60) + "\n"
	output += "OSINT TIPS:\n"
	output += "  - Use -u \"username\" to check a specific username in detail\n"
	output += "  - The most valuable usernames are those found on multiple platforms\n"
	output += "  - Check email patterns: username@gmail.com, username@outlook.com\n"

	return output
}