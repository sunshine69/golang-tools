package gitlabutils

import (
	"testing"
	"github.com/xanzy/go-gitlab"
	u "localhost.com/utils"
)

func TestGetNameSpace(t *testing.T) {
	git, err := gitlab.NewClient(u.Getenv( "GITLABTOKEN", ""), gitlab.WithBaseURL(u.Getenv("GITLABAPIBASEURL","")))
	u.CheckErr(err, "")
	GetNameSpace(git, "Team DevOps")

}
