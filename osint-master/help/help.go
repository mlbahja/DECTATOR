package help

import (
	"fmt"
	"strings"

)

// UsernameGenerator generates possible usernames from a full name
type UsernameGenerator struct {
	FirstName string
	LastName  string
}

// GenerateAllUsernames creates a list of possible username variations
func (ug *UsernameGenerator) GenerateAllUsernames() []string {
	usernames := make(map[string]bool) // Use map to avoid duplicates

	// Clean the names
	firstName := strings.ToLower(strings.TrimSpace(ug.FirstName))
	lastName := strings.ToLower(strings.TrimSpace(ug.LastName))
	firstInitial := ""
	if len(firstName) > 0 {
		firstInitial = string(firstName[0])
	}
	lastInitial := ""
	if len(lastName) > 0 {
		lastInitial = string(lastName[0])
	}

	// 1. First name variations
	usernames[firstName] = true
	usernames[firstName+"1"] = true
	usernames[firstName+"12"] = true
	usernames[firstName+"123"] = true
	
	// 2. Last name variations
	if lastName != "" {
		usernames[lastName] = true
		usernames[lastName+"1"] = true
		usernames[lastName+"12"] = true
	}
	
	// 3. First + Last
	if lastName != "" {
		usernames[firstName+lastName] = true
		usernames[firstName+"."+lastName] = true
		usernames[firstName+"_"+lastName] = true
		usernames[firstName+"-"+lastName] = true
	}
	
	
	if lastName != "" {
		usernames[lastName+firstName] = true
		usernames[lastName+"."+firstName] = true
		usernames[lastName+"_"+firstName] = true
	}
	
	// 5. First initial + Last name
	if firstInitial != "" && lastName != "" {
		usernames[firstInitial+lastName] = true
		usernames[firstInitial+"."+lastName] = true
		usernames[firstInitial+"_"+lastName] = true
		usernames[firstInitial+"-"+lastName] = true
	}
	
	// 6. First name + Last initial
	if firstName != "" && lastInitial != "" {
		usernames[firstName+lastInitial] = true
		usernames[firstName+"."+lastInitial] = true
		usernames[firstName+"_"+lastInitial] = true
	}
	
	// 7. First initial + Last initial + numbers
	if firstInitial != "" && lastInitial != "" {
		usernames[firstInitial+lastInitial] = true
		usernames[firstInitial+lastInitial+"1"] = true
		usernames[firstInitial+lastInitial+"12"] = true
		usernames[firstInitial+lastInitial+"123"] = true
	}
	
	// 8. Truncated variations (first 3-6 letters)
	if len(firstName) >= 4 {
		usernames[firstName[:3]] = true
		usernames[firstName[:4]] = true
		if len(firstName) >= 5 {
			usernames[firstName[:5]] = true
		}
		if len(firstName) >= 6 {
			usernames[firstName[:6]] = true
		}
	}
	
	// 9. Add common suffixes
	suffixes := []string{"", "1", "12", "123", "2023", "2024", "_", ".", "-"}
	baseNames := []string{firstName}
	if lastName != "" {
		baseNames = append(baseNames, lastName, firstName+lastName, firstInitial+lastName)
	}
	
	for _, base := range baseNames {
		for _, suffix := range suffixes {
			if suffix == "" {
				usernames[base] = true
			} else {
				usernames[base+suffix] = true
				usernames[base+"_"+suffix] = true
				usernames[base+"."+suffix] = true
			}
		}
	}
	
	// 10. Add common prefixes
	prefixes := []string{"the", "real", "im", "its"}
	for _, prefix := range prefixes {
		if firstName != "" {
			usernames[prefix+firstName] = true
			usernames[prefix+"_"+firstName] = true
			usernames[prefix+"."+firstName] = true
		}
		if lastName != "" {
			usernames[prefix+lastName] = true
		}
	}
	
	// Convert map to slice
	result := make([]string, 0, len(usernames))
	for username := range usernames {
		if len(username) >= 3 && len(username) <= 30 { // Reasonable username length
			result = append(result, username)
		}
	}
	
	return result
}

// GenerateFromFullName creates username variations from a full name string
func GenerateFromFullName(fullName string) []string {
	parts := strings.Fields(fullName)
	if len(parts) == 0 {
		return []string{}
	}
	
	firstName := parts[0]
	lastName := ""
	if len(parts) > 1 {
		lastName = strings.Join(parts[1:], " ")
	}
	
	generator := &UsernameGenerator{
		FirstName: firstName,
		LastName:  lastName,
	}
	
	return generator.GenerateAllUsernames()
}

// GenerateUsernameReport creates a report of generated usernames
func GenerateUsernameReport(fullName string) string {
	usernames := GenerateFromFullName(fullName)
	
	if len(usernames) == 0 {
		return "Error: Could not generate usernames from provided name\n"
	}
	
	output := fmt.Sprintf("Generated Usernames from: %s\n", fullName)
	output += strings.Repeat("=", 50) + "\n\n"
	output += fmt.Sprintf("Total variations: %d\n\n", len(usernames))
	
	// Display in columns
	output += "POSSIBLE USERNAMES:\n"
	for i, username := range usernames {
		if i < 50 { // Limit to first 50 to avoid spam
			output += fmt.Sprintf("  - %s\n", username)
		} else if i == 50 {
			output += fmt.Sprintf("  ... and %d more\n", len(usernames)-50)
			break
		}
	}
	
	output += "\n" + strings.Repeat("=", 50) + "\n"
	output += "OSINT TIPS:\n"
	output += "  - Use these usernames with the -u flag to check existence\n"
	output += "  - Common patterns: first.last, flast, firstlast, first_last\n"
	output += "  - Add numbers (123, 2024) or special chars (_, .)\n"
	output += "  - Check email patterns: username@gmail.com, username@outlook.com\n"
	
	return output
}