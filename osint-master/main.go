package main

import (
	"flag"
	"fmt"
	"os"

	"osint-master/handlers"
)

func main() {
	
	flag.Usage = func() {

	fmt.Println("OSINT MASTER")
	fmt.Println("============")
	fmt.Println()

	fmt.Println("USAGE:")
	fmt.Println("  osintmaster [OPTION]")
	fmt.Println()

	fmt.Println("OPTIONS:")
	fmt.Println(`  -i "IP Address"   Lookup IP information`)
	fmt.Println(`  -u "Username"     Search username on platforms`)
	fmt.Println(`  -d "Domain"       Enumerate subdomains`)
	fmt.Println()
	fmt.Println("============")
	fmt.Println(`  -n "Full Name"    Search information by full name`)
	fmt.Println(`  -g "Full Name"    Generate and test usernames`)
	fmt.Println(`  -o "File"         Save output to file`)
	fmt.Println()

	fmt.Println("EXAMPLES:")
	fmt.Println(`  osintmaster -i 8.8.8.8`)
	fmt.Println(`  osintmaster -u torvalds`)
	fmt.Println(`  osintmaster -g "Linus Torvalds"`)
	fmt.Println(`  osintmaster -n "John Smith"`)
	fmt.Println(`  osintmaster -d github.com`)
	fmt.Println(`  osintmaster -i 8.8.8.8 -o output/ip.txt`)
}

	name := flag.String("n", "", "")
	ip := flag.String("i", "", "")
	username := flag.String("u", "", "")
	generate := flag.String("g", "", "") // This is the flag for generate and test
	domain := flag.String("d", "", "")
	output := flag.String("o", "", "")

	if len(os.Args) > 1 {
		if os.Args[1] == "--help" || os.Args[1] == "-h" {
			flag.Usage()
			return
		}
	}

	flag.Parse()

	// Show help if no args
	if len(os.Args) == 1 {
		flag.Usage()
		return
	}

	// Ensure only one main option is used
	options := 0
	list := []string{*name, *ip, *username, *generate,*domain}
	for _, c := range list {
		if c != "" {
			options++
		}
	}




	if options == 0 {
		fmt.Println("Error: You must provide one of -n, -i, -u, -g, or -d")
		return
	}
	

	if options > 1 {
		fmt.Println("Error: Use only ONE of -n, -i, -u, -g, or -d")
		return
	}

	// Dispatch
	var result string

	switch {
		
		
	case *ip != "":
		result = handlers.HandleIP(*ip)
	case *username != "":


		
		result = handlers.HandleUsername(*username)
	case *domain != "":
		result = handlers.HandleDomain(*domain)

		
	//bonuss ========================================	
	case *name != "":
		result = handlers.HandleNameScraper(*name)
	case *generate != "":
		// This will generate AND test usernames
		result = handlers.HandleGenerateAndTestUsernames(*generate)

	}

	// Output
	fmt.Println(result)

	if *output != "" {
		handlers.SaveToFile(*output, result)
	}
}
