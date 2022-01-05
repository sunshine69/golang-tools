package main
import (
	"os"
	"bufio"
	"io/ioutil"
	"fmt"
	"log"
	"testing"
	. "localhost.com/gitlab/model"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
	u "localhost.com/utils"
)
// Run like this to experiment/addhoc logic. Make a function Test_XXXX
//go test --tags "sqlite_stat4 sqlite_foreign_keys sqlite_json" -timeout 30s -run '^Test_XXXX' -v

func TestGetGitlabProject(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	p, _, err := git.Projects.GetProject(1370, nil); u.CheckErr(err, "GetProject")
	log.Printf("[DEBUG] TestGetGitlabProject %s\n", u.JsonDump(p, "  "))
	approvalRules, _, err := git.Projects.GetProjectApprovalRules(p.ID, nil)
	u.CheckErr(err, "   ")
	log.Printf("approvalRules: %s\n",u.JsonDump(approvalRules, "  "))
}
func TestGitlabGroupVar(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	gv, _, err := git.GroupVariables.GetVariable(463, "DEPLOYMENT_APP_ID", nil)
	u.CheckErr(err, "TestGitlabGroupVar")
	log.Printf("%s\n",u.JsonDump(gv, "  "))
}
func TestCreateProject(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	path,newNameSpaceId := "stevek-test-temp", 558
	_, _, err := git.Projects.CreateProject(&gitlab.CreateProjectOptions{
		Path: &path,
		NamespaceID: &newNameSpaceId,
	})
	log.Printf("DEBUG: %s\n", err.Error())
	// u.CheckErr(err, "Test CreateProject")
}
func TestSearchProject(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	path := "stevek-test-temp"
	ps, _, err := git.Projects.ListProjects(&gitlab.ListProjectsOptions {
		Search: &path,
	})
	u.CheckErrNonFatal(err, "")
	log.Printf("DEBUG: %s\n", u.JsonDump(ps, "  "))
	// u.CheckErr(err, "Test CreateProject")
}
func TestGetGitlabUser(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git, userActive := GetGitlabClient(), true
	users, _, err := git.Users.ListUsers(&gitlab.ListUsersOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1,
			PerPage: 1,
		},
		Active: &userActive,
	})
	u.CheckErr(err, "ListUsers")
	log.Printf("%s\n", u.JsonDump(users,  "  "))
}
func TestAddhoc_backup_delete_vars_by_value(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	Addhoc_backup_delete_vars_by_value(git, "microservice.cluster-csb6wde17f7d.ap-southeast-2.rds.amazonaws.com")
}
func TestCopyGroupVars(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	opt := gitlab.ListGroupVariablesOptions{
		Page: 1,
		PerPage: 100,
	}
	allVars := []*gitlab.GroupVariable{}
	projectIDLookup := map[string]int{
		"go1-core": 266,
		"microservices": 146,
		"integration": 227,
		"domain-content": 569,
	}
	groupName := "domain-content"
	for {
		gA, resp, err := git.Groups.GetGroup(projectIDLookup[groupName], nil); u.CheckErr(err, "")
		gVars,_,err := git.GroupVariables.ListVariables(gA.ID, &opt); u.CheckErr(err, "CopyGroupVars ListVariables")
		allVars = append(allVars, gVars... )
		// gB, _, err := git.Groups.GetGroup(569, nil); u.CheckErr(err, "")
		// CopyGroupVars(git, gA, gB)
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		opt.Page = resp.NextPage
	}
	// log.Printf("%s\nCount: %d\n", u.JsonDump(allVars, "   "), len(allVars))
	ioutil.WriteFile("data/"+groupName + "-vars.json", []byte(u.JsonDump(allVars, "  ")), 0750)
}
func TestAllTeamShouldHaveReporterPermmisiononOnAllProject(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	AllTeamShouldHaveReporterPermmisiononOnAllProject(git)
}
func TestTransferProjectQuick(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	TransferProjectQuick(git, 2414, "mirror/go1-core/group/services", "")
}
func TestDeleteGroup(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	groupID := 714
	g, _, err := git.Groups.GetGroup(groupID, nil); u.CheckErr(err, "TestDeleteGroup GetGroup")
	log.Printf("YOU ARE GOING TO REMOVE THIS GROUP. Type YES to continue, otherwise I wont do it. %s\n", u.JsonDump(g, "  "))
	// var confirm string
    // fmt.Scanf("%s", &confirm)
	rd,_,err := os.Pipe(); t.Fatal(err)
	saved := os.Stdin
	os.Stdin = rd
	scanner := bufio.NewScanner(rd)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		u.CheckErr(err, "")
	}
	confirm := scanner.Text()
	os.Stdin = saved
	if confirm == "YES"{
		fmt.Println("Your answer ", confirm)
		// res, err :=  git.Groups.DeleteGroup(714, nil)
		// u.CheckErr(err, "TestDeleteGroup")
		// log.Printf("[DEBUG] %s\n", u.JsonDump(res, "  "))
	}
}