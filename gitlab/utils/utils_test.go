package gitlabutils

import (
	"testing"

	u "github.com/sunshine69/golang-tools/utils"
	"github.com/xanzy/go-gitlab"
)

func TestGetNameSpace(t *testing.T) {
	git, err := gitlab.NewClient(u.Getenv("GITLABTOKEN", ""), gitlab.WithBaseURL(u.Getenv("GITLABAPIBASEURL", "")))
	u.CheckErr(err, "")
	GetNameSpace(git, "Team DevOps")

}
