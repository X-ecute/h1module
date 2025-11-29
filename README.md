export HACKERONE_USERNAME="your_username"

export HACKERONE_TOKEN="your_api_token"

# Get all programs with pagination and display them
go run h1module.go programs-all

# Get all programs and save to a file
go run h1module.go programs-all-save all_programs.json

# Get single page of programs (legacy behavior)
go run h1module.go programs