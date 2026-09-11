package buildinfo

import (
	"testing"
)

func TestPrintBuildDetails(t *testing.T) {

	origGitSummary := GitSummary
	origGitBranch := GitBranch
	origBuildDate := BuildDate

	defer func() {
		GitSummary = origGitSummary
		GitBranch = origGitBranch
		BuildDate = origBuildDate
	}()

	t.Run("prints build details when GitSummary is set", func(t *testing.T) {

		GitSummary = "v1.0.0"
		GitBranch = "main"
		BuildDate = "2025-01-01"

		PrintBuildDetails()

	})

	t.Run("does not print when GitSummary is empty", func(t *testing.T) {

		GitSummary = ""
		GitBranch = "main"
		BuildDate = "2025-01-01"

		PrintBuildDetails()
	})

	t.Run("handles empty branch and date", func(t *testing.T) {
		GitSummary = "v1.0.0"
		GitBranch = ""
		BuildDate = ""

		PrintBuildDetails()
	})
}
