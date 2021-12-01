package main
import (
	"io/ioutil"
	"os"
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
func TestGetGitlabGroup(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()

	childGroup := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("parent_id = %d", 584)})
	log.Printf("[DEBUG] %s\n",u.JsonDump(childGroup,"  "))
}
func TestGetGitlabProjects(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
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
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	ns, _, err := git.Namespaces.SearchNamespace("Domain -", nil); u.CheckErr(err, "SearchNamespace")
	for _, row := range ns {
		mygroup, _, _ := git.Groups.GetGroup(row.ID, nil)
		// log.Printf("GROUP %s\n", u.JsonDump(mygroup, "  "))
		if row.ParentID == 0 {//Root group, no parent
			if row.MembersCountWithDescendants > 0 {//Having a subgroup or project/domain
				//Find projects
				// ps := ProjectGet(map[string]string{"where": fmt.Sprintf("namespace_id = %d", row.ID)})
				// log.Printf("%s\n", u.JsonDump(ps, "  "))
				if mygroup.Description == "autocreated" {
					fmt.Printf("%s\n", mygroup.Path)
				}
			}
		}
		// log.Printf("%s\n", u.JsonDump(row, "    "))
	}
}
func TestGetProjectFromDomain(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()

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
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()

	domains := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("name LIKE 'Domain - Recommendation'")})
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
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
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
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	gm := GroupmemberGet(map[string]string{"sql": "select group_id from groupmember where member_group_id =  544 group by group_id"})
	log.Printf("%s\n",u.JsonDump(gm,"  "))
}
func TestProjectContainterRegistry(t *testing.T) {
	log.Println("started")
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	returnTag := true
	registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(2337, &gitlab.ListRegistryRepositoriesOptions{
		ListOptions: gitlab.ListOptions{
			Page: 1, PerPage: 500,
		},
		Tags: &returnTag,
		TagsCount: &returnTag,
	}); u.CheckErr(err, "ProcessTransferProjectRegistry ListRegistryRepositories")
	apibaseurl := git.BaseURL()
	p, _, _ := git.Projects.GetProject(2337, nil)
	registryBase := fmt.Sprintf("registry.%s/%s", apibaseurl.Hostname(), p.PathWithNamespace)
	log.Println(registryBase)
	for _, repoReg := range registryRepos {
		// _, tags := repoReg.Location, repoReg.Tags
		// for _, t := range tags{
			// log.Printf("%s:%s", registryBase, t.Name )
			//u.RunSystemCommand(fmt.Sprintf(`docker pull %s:%s`, location, t), true)
		// }
		log.Printf("%s\n",u.JsonDump(repoReg, "  "))
	}
}
func TestRunSystemCmd(t *testing.T) {
	f, err := os.OpenFile("log/testlogfile.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	u.CheckErr(err, "OpenFile Log")
	defer f.Close()
	log.SetOutput(f)

	log.Println( u.RunSystemCommand("ls $HOME", true))
	log.SetOutput(os.Stdout)
	log.Printf("REACH HERE\n")
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
func TestWaitProjectContainerRegistryTagsCountEqualZero(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	ParseConfig()
	git := GetGitlabClient()
	returnTag := true
	for {
		registryRepos, _, err := git.ContainerRegistry.ListRegistryRepositories(2414, &gitlab.ListRegistryRepositoriesOptions{
			ListOptions: gitlab.ListOptions{
				Page: 1, PerPage: 500,
			},
			Tags: &returnTag,
			TagsCount: &returnTag,
		}); u.CheckErr(err, "MoveProjectRegistryImages ListRegistryRepositories")
		if len(registryRepos) == 0 {
			log.Printf("No repo, no tags")
			break
		} else {
			u.Sleep("15s")
		}
	}
}
func TestParsingConfig(t *testing.T) {
	ConfigFile, Logdbpath = "/home/stevek/.dump-gitlab-project-data.json",  "data/testdb.sqlite3"
	AppConfig := u.ParseConfig(ConfigFile)
	log.Printf("%d\n", AppConfig["admin_user_id"])
}
func TestMakeGitlabPathNameFromName(t *testing.T) {
	gPath := MakeGitlabPathNameFromName("Domain - External API")
	log.Printf(gPath)
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