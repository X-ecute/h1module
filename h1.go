package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// H1Client represents the HackerOne API client
type H1Client struct {
	Username      string
	APIToken      string
	BaseURL       string
	RateLimitDelay time.Duration
}

// Program represents a HackerOne program
type Program struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Handle         string `json:"handle"`
		Name           string `json:"name"`
		Currency       string `json:"currency"`
		Policy         string `json:"policy"`
		State          string `json:"state"`
		OffersBounties bool   `json:"offers_bounties"`
		OpenScope      bool   `json:"open_scope"`
	} `json:"attributes"`
}

// ProgramsResponse represents the response from getting all programs
type ProgramsResponse struct {
	Data  []Program         `json:"data"`
	Links map[string]string `json:"links"`
}

// StructuredScope represents a scope entry in a program
type StructuredScope struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		AssetType             string `json:"asset_type"`
		AssetIdentifier       string `json:"asset_identifier"`
		EligibleForBounty     bool   `json:"eligible_for_bounty"`
		EligibleForSubmission bool   `json:"eligible_for_submission"`
		Instruction           string `json:"instruction"`
		MaxSeverity           string `json:"max_severity"`
	} `json:"attributes"`
}

// StructuredScopesResponse represents the response from getting structured scopes
type StructuredScopesResponse struct {
	Data  []StructuredScope `json:"data"`
	Links map[string]string `json:"links"`
}

// Weakness represents a weakness/CWE entry
type Weakness struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		ExternalID  string `json:"external_id"`
	} `json:"attributes"`
}

// WeaknessesResponse represents the response from getting weaknesses
type WeaknessesResponse struct {
	Data  []Weakness        `json:"data"`
	Links map[string]string `json:"links"`
}

// NewH1Client creates a new HackerOne API client
func NewH1Client(username, token string) *H1Client {
	return &H1Client{
		Username:      username,
		APIToken:      token,
		BaseURL:       "https://api.hackerone.com/v1/hackers",
		RateLimitDelay: 100 * time.Millisecond, // 600 requests per minute = ~100ms between requests
	}
}

// makeRequest makes an authenticated request to the HackerOne API
func (c *H1Client) makeRequest(method, endpoint string) ([]byte, error) {
	url := c.BaseURL + endpoint

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.Username, c.APIToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// GetAllProgramsPaginated gets all programs with pagination support
func (c *H1Client) GetAllProgramsPaginated() ([]Program, error) {
	var allPrograms []Program
	nextURL := "/programs"
	page := 1

	for nextURL != "" {
		fmt.Printf("Fetching page %d...\n", page)

		body, err := c.makeRequest("GET", nextURL)
		if err != nil {
			return nil, fmt.Errorf("error fetching page %d: %v", page, err)
		}

		var response ProgramsResponse
		err = json.Unmarshal(body, &response)
		if err != nil {
			return nil, fmt.Errorf("error parsing page %d: %v", page, err)
		}

		allPrograms = append(allPrograms, response.Data...)
		fmt.Printf("Page %d: fetched %d programs (total: %d)\n", page, len(response.Data), len(allPrograms))

		// Check for next page
		if nextLink, exists := response.Links["next"]; exists && nextLink != "" {
			// Extract just the endpoint part from the full URL
			nextURL = extractEndpoint(nextLink)
			page++

			// Respect rate limit
			time.Sleep(c.RateLimitDelay)
		} else {
			nextURL = ""
		}
	}

	return allPrograms, nil
}

// extractEndpoint extracts the API endpoint from a full URL
func extractEndpoint(fullURL string) string {
	// Remove the base URL part to get just the endpoint
	baseURL := "https://api.hackerone.com/v1/hackers"
	if strings.HasPrefix(fullURL, baseURL) {
		return strings.TrimPrefix(fullURL, baseURL)
	}
	return fullURL
}

// SaveProgramsToFile saves programs to a JSON file
func SaveProgramsToFile(programs []Program, filename string) error {
	file, err := json.MarshalIndent(programs, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, file, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully saved %d programs to %s\n", len(programs), filename)
	return nil
}

// Mode 1: Get Structured Scopes for a program
func (c *H1Client) GetStructuredScopes(programHandle string) (*StructuredScopesResponse, error) {
	endpoint := fmt.Sprintf("/programs/%s/structured_scopes", programHandle)
	body, err := c.makeRequest("GET", endpoint)
	if err != nil {
		return nil, err
	}

	var response StructuredScopesResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Mode 2: Get Weaknesses for a program
func (c *H1Client) GetWeaknesses(programHandle string) (*WeaknessesResponse, error) {
	endpoint := fmt.Sprintf("/programs/%s/weaknesses", programHandle)
	body, err := c.makeRequest("GET", endpoint)
	if err != nil {
		return nil, err
	}

	var response WeaknessesResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Mode 3: Get All Programs (single page - legacy)
func (c *H1Client) GetAllPrograms() (*ProgramsResponse, error) {
	body, err := c.makeRequest("GET", "/programs")
	if err != nil {
		return nil, err
	}

	var response ProgramsResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Mode 4: Get Specific Program
func (c *H1Client) GetProgram(programHandle string) (*Program, error) {
	endpoint := fmt.Sprintf("/programs/%s", programHandle)
	body, err := c.makeRequest("GET", endpoint)
	if err != nil {
		return nil, err
	}

	var response struct {
		Data Program `json:"data"`
	}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response.Data, nil
}

// PrintStructuredScopes displays structured scopes in a readable format
func PrintStructuredScopes(scopes *StructuredScopesResponse, programHandle string) {
	fmt.Printf("\n=== Structured Scopes for %s ===\n", programHandle)
	fmt.Printf("Found %d scope entries\n\n", len(scopes.Data))

	for i, scope := range scopes.Data {
		fmt.Printf("%d. Asset: %s\n", i+1, scope.Attributes.AssetIdentifier)
		fmt.Printf("   Type: %s\n", scope.Attributes.AssetType)
		fmt.Printf("   Bounty Eligible: %t\n", scope.Attributes.EligibleForBounty)
		fmt.Printf("   Submission Eligible: %t\n", scope.Attributes.EligibleForSubmission)
		fmt.Printf("   Max Severity: %s\n", scope.Attributes.MaxSeverity)
		if scope.Attributes.Instruction != "" {
			fmt.Printf("   Instructions: %s\n", scope.Attributes.Instruction)
		}
		fmt.Println()
	}
}

// PrintWeaknesses displays weaknesses in a readable format
func PrintWeaknesses(weaknesses *WeaknessesResponse, programHandle string) {
	fmt.Printf("\n=== Weaknesses for %s ===\n", programHandle)
	fmt.Printf("Found %d weakness types\n\n", len(weaknesses.Data))

	for i, weakness := range weaknesses.Data {
		fmt.Printf("%d. %s (CWE-%s)\n", i+1, weakness.Attributes.Name, weakness.Attributes.ExternalID)
		fmt.Printf("   Description: %s\n", weakness.Attributes.Description)
		fmt.Println()
	}
}

// PrintPrograms displays programs in a readable format
func PrintPrograms(programs []Program) {
	fmt.Printf("\n=== All Programs ===\n")
	fmt.Printf("Found %d programs\n\n", len(programs))

	for i, program := range programs {
		fmt.Printf("%d. %s (%s)\n", i+1, program.Attributes.Name, program.Attributes.Handle)
		fmt.Printf("   State: %s\n", program.Attributes.State)
		fmt.Printf("   Offers Bounties: %t\n", program.Attributes.OffersBounties)
		fmt.Printf("   Open Scope: %t\n", program.Attributes.OpenScope)
		fmt.Printf("   Currency: %s\n", program.Attributes.Currency)
		fmt.Println()
	}
}

// PrintProgram displays a single program in detail
func PrintProgram(program *Program) {
	fmt.Printf("\n=== Program Details ===\n")
	fmt.Printf("Name: %s\n", program.Attributes.Name)
	fmt.Printf("Handle: %s\n", program.Attributes.Handle)
	fmt.Printf("State: %s\n", program.Attributes.State)
	fmt.Printf("Currency: %s\n", program.Attributes.Currency)
	fmt.Printf("Offers Bounties: %t\n", program.Attributes.OffersBounties)
	fmt.Printf("Open Scope: %t\n", program.Attributes.OpenScope)
	if program.Attributes.Policy != "" {
		fmt.Printf("Policy: %s\n", program.Attributes.Policy)
	}
}

func main() {
	// Get credentials from environment variables
	username := os.Getenv("HACKERONE_USERNAME")
	token := os.Getenv("HACKERONE_TOKEN")

	if username == "" || token == "" {
		log.Fatal("Please set HACKERONE_USERNAME and HACKERONE_TOKEN environment variables")
	}

	client := NewH1Client(username, token)

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  h1module scopes <program_handle>        - Get structured scopes for a program")
		fmt.Println("  h1module weaknesses <program_handle>    - Get weaknesses for a program")
		fmt.Println("  h1module programs                       - Get all programs (single page)")
		fmt.Println("  h1module programs-all                   - Get ALL programs with pagination")
		fmt.Println("  h1module programs-all-save <filename>   - Get ALL programs and save to file")
		fmt.Println("  h1module program <program_handle>       - Get specific program details")
		return
	}

	mode := os.Args[1]

	switch strings.ToLower(mode) {
	case "scopes":
		if len(os.Args) < 3 {
			log.Fatal("Please provide a program handle")
		}
		programHandle := os.Args[2]

		scopes, err := client.GetStructuredScopes(programHandle)
		if err != nil {
			log.Fatalf("Error getting structured scopes: %v", err)
		}
		PrintStructuredScopes(scopes, programHandle)

	case "weaknesses":
		if len(os.Args) < 3 {
			log.Fatal("Please provide a program handle")
		}
		programHandle := os.Args[2]

		weaknesses, err := client.GetWeaknesses(programHandle)
		if err != nil {
			log.Fatalf("Error getting weaknesses: %v", err)
		}
		PrintWeaknesses(weaknesses, programHandle)

	case "programs":
		programs, err := client.GetAllPrograms()
		if err != nil {
			log.Fatalf("Error getting programs: %v", err)
		}
		PrintPrograms(programs.Data)

	case "programs-all":
		programs, err := client.GetAllProgramsPaginated()
		if err != nil {
			log.Fatalf("Error getting all programs: %v", err)
		}
		PrintPrograms(programs)

	case "programs-all-save":
		if len(os.Args) < 3 {
			log.Fatal("Please provide a filename")
		}
		filename := os.Args[2]

		programs, err := client.GetAllProgramsPaginated()
		if err != nil {
			log.Fatalf("Error getting all programs: %v", err)
		}

		err = SaveProgramsToFile(programs, filename)
		if err != nil {
			log.Fatalf("Error saving to file: %v", err)
		}

	case "program":
		if len(os.Args) < 3 {
			log.Fatal("Please provide a program handle")
		}
		programHandle := os.Args[2]

		program, err := client.GetProgram(programHandle)
		if err != nil {
			log.Fatalf("Error getting program: %v", err)
		}
		PrintProgram(program)

	default:
		log.Fatal("Invalid mode. Use: scopes, weaknesses, programs, programs-all, programs-all-save, or program")
	}
}