package main
import (
	"log"
	"testing"
	. "localhost.com/gitlab/model"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
	u "localhost.com/utils"
)

func TestProject(t *testing.T) {
	Logdbpath = "testdb.sqlite3"
}
func TestGetGitlabProject(t *testing.T) {
	ConfigFile = "/home/stevek/.dump-gitlab-project-data.json"
	git := GetGitlabClient()
	p, _, err := git.Projects.GetProject(1399, nil); u.CheckErr(err, "GetProject")
	log.Printf("[DEBUG] %s\n", p.CreatedAt.Format(u.CleanStringDateLayout) )
}
func TestGetGitlabProjects(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "testdb.sqlite3"
	git := GetGitlabClient()
	ps, _, err := git.Projects.ListProjects(&gitlab.ListProjectsOptions{
		ListOptions: gitlab.ListOptions{
			Page:1, PerPage: 1,
		},
	}); u.CheckErr(err, "GetProject")
	for _, p := range ps {
		log.Printf("[DEBUG] %s\n", p.PathWithNamespace )
		localp := Project{}
		localp.GetOneOrNew(p.PathWithNamespace)
		log.Printf("[DEBUG] %s\n",u.JsonDump(localp,"  "))
		localp.GitlabCreatedAt = p.CreatedAt.Format(u.CleanStringDateLayout)
		localp.Update()
		log.Printf("[DEBUG1] %s\n",u.JsonDump(localp,"  "))
	}
}
