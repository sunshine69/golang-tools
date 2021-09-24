package main
import (
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
	ConfigFile = "/home/stevek/.dump-gitlab-project-data.json"
	git := GetGitlabClient()
	p, _, err := git.Projects.GetProject(1399, nil); u.CheckErr(err, "GetProject")
	log.Printf("[DEBUG] %s\n", p.CreatedAt.Format(u.CleanStringDateLayout) )
}
func TestGetGitlabGroup(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "testdb.sqlite3"
	// git := GetGitlabClient()
	// childGroup := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("parent_id = %d AND name LIKE 'Team - %%'", 188)})
	childGroup := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("parent_id = %d", 584)})
	log.Printf("[DEBUG] %s\n",u.JsonDump(childGroup,"  "))
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
		localp := ProjectNew(p.PathWithNamespace)
		log.Printf("[DEBUG] %s\n",u.JsonDump(localp,"  "))
		localp.GitlabCreatedAt = p.CreatedAt.Format(u.CleanStringDateLayout)
		localp.Update()
		log.Printf("[DEBUG1] %s\n",u.JsonDump(localp,"  "))
	}
}
func TestGitDomain(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "testdb.sqlite3"
	git := GetGitlabClient()
	ns, _, err := git.Namespaces.SearchNamespace("Domain - Users", nil); u.CheckErr(err, "SearchNamespace")
	for _, row := range ns {
		mygroup, _, _ := git.Groups.GetGroup(row.ID, nil)
		log.Printf("GROUP %s\n", u.JsonDump(mygroup, "  "))
		if row.ParentID == 0 {//Root group, no parent
			if row.MembersCountWithDescendants > 0 {//Having a subgroup or project/domain
				//Find projects
				ps := ProjectGet(map[string]string{"where": fmt.Sprintf("namespace_id = %d", row.ID)})
				log.Printf("%s\n", u.JsonDump(ps, "  "))
			}
		}
		// log.Printf("%s\n", u.JsonDump(row, "    "))
	}
}
func TestGetProjectFromDomain(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "testdb.sqlite3"
	domains := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("name LIKE 'Domain - Recommendation'")})
	for _, row := range domains {
		if row.ParentId == 0 {//Root group, no parent
			if row.MembersCountWithDescendants > 0 {//Having a subgroup or project/domain
				//Find projects
				ps := ProjectGet(map[string]string{"where": fmt.Sprintf("namespace_id = %d", row.GitlabNamespaceId)})
				log.Printf("PROJECT %s\n", u.JsonDump(ps, "  "))
			}
		}
	}
}
func TestGetMemberFromDomain(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "testdb.sqlite3"
	domains := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("name LIKE 'Domain - Recommendation'")})
	git := GetGitlabClient()
	for _, row := range domains {
		log.Printf("%s\n", u.JsonDump(row, "  "))
		if row.ParentId == 0 && row.MembersCountWithDescendants > 0 {
			// this return a member as User kind, not group kind. No it seems this feature is new, gitlab api not supported yet
			users, _, err := git.Groups.ListGroupMembers(row.GitlabNamespaceId, &gitlab.ListGroupMembersOptions{
				ListOptions: gitlab.ListOptions{
					Page:1, PerPage:100,
				},
			}); u.CheckErr(err, "Groups.ListGroupMembers")
			log.Printf("%s\n", u.JsonDump(users,"  "))
			groups, _, err := git.Groups.ListAllGroupMembers(row.GitlabNamespaceId, &gitlab.ListGroupMembersOptions {
				ListOptions: gitlab.ListOptions{
					Page:1, PerPage:100,
				},
			}); u.CheckErr(err, "Groups.ListGroupMembers")
			log.Printf("%s\n", u.JsonDump(groups,"  "))
		}
	}
}
func TestProjectMigrationStatus(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "testdb.sqlite3"
	git := GetGitlabClient()
	dbc := GetDBConn()
	defer dbc.Close()
	domains := GroupmemberGet(map[string]string{"where": "group_id = 541"})
	for _, row := range domains {
		ps, _, err := git.Groups.ListGroupProjects(row.GroupId, nil)
		u.CheckErr(err, "ReportProjectMigrationStatus ListGroupProjects")
		log.Printf("Count project %d\n",len(ps))
		for _, p := range ps {
			aP := ProjectNew(p.PathWithNamespace)
			aP.DomainOwnershipConfirmed = 1
			aP.Update()
			// log.Printf("[DEBUG] project %s\n", u.JsonDump(p, "  "))
		}
	}
	// Output and write csv file use sqlitebrowser better
}
func TestRawSQL(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "testdb.sqlite3"
	gm := GroupmemberGet(map[string]string{"sql": "select group_id from groupmember where member_group_id =  544 group by group_id"})
	log.Printf("%s\n",u.JsonDump(gm,"  "))
}
