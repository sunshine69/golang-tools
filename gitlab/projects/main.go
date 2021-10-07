package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"
	"os"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
)

var (
    action string
)

func ParseConfig() {
	if ConfigFile == "" {
		log.Fatalf("Config file required. Run with -h for help")
	}
	AppConfig = u.ParseConfig(ConfigFile)
	log.Printf("[DEBUG] AppConfig %s\n",u.JsonDump(AppConfig,"  "))
	if SearchStr == "" && AppConfig["SearchStr"].(string) != "" {
		SearchStr = AppConfig["SearchStr"].(string)
	}
}
func DumpOrUpdateProject(git *gitlab.Client, SearchStr string) {
	log.Printf("DumpOrUpdateProject Started\n")
	opt := &gitlab.ListProjectsOptions{
		Search: gitlab.String(SearchStr),
		ListOptions: gitlab.ListOptions{
			PerPage: 25,
			Page:    1,
		},
	}
	projectService := git.Projects
	for {
		var (
			projects []*gitlab.Project
			project  *gitlab.Project
			resp     *gitlab.Response
			err      error
		)
		projectID, err := strconv.Atoi(SearchStr)
		if err == nil {
			project, resp, err = projectService.GetProject(projectID, nil)
			u.CheckErr(err, "GetProject")
			projects = []*gitlab.Project{project}
		} else {
			projects, resp, err = projectService.ListProjects(opt)
			u.CheckErr(err, "Projects.ListProjects")
		}
		for _, row := range projects {
			if ProjectFilter() {
				p := ProjectNew(row.PathWithNamespace)
				log.Printf("[DEBUG] Project %s - \n", u.JsonDump(p, "    "))
				if row.Owner != nil {
					p.OwnerId = row.Owner.ID
					p.OwnerName = row.Owner.Name
				} else {
					p.OwnerId = -1
					p.OwnerName = "null"
				}
				p.TagList = strings.Join(row.Topics, ",")
                labels, _, err := git.Labels.ListLabels(row.ID, &gitlab.ListLabelsOptions{
                    ListOptions: gitlab.ListOptions{
                        Page: 1, PerPage: 100,
                    },
                })
                u.CheckErr(err, "Project Labels.ListLabels")
                labelList := []string{}
                for _, _label := range labels {
                    labelList = append(labelList, _label.Name)
                }
				p.Pid, p.Weburl, p.Name, p.NameWithSpace, p.Path, p.PathWithNamespace, p.NamespaceKind, p.NamespaceName, p.NamespaceId, p.GitlabCreatedAt, p.Labels = row.ID, row.WebURL, row.Name, row.NameWithNamespace, row.Path, row.PathWithNamespace, row.Namespace.Kind, row.Namespace.Name, row.Namespace.ID, row.CreatedAt.Format(u.CleanStringDateLayout), strings.Join(labelList, ",")
				if ! strings.Contains(p.PathWithNamespace, "domain-") { p.DomainOwnershipConfirmed = 0 }
				p.Update()
                UpdateTeamProject(git, row)
			}
		}
		// Exit the loop when we've seen all pages.
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		u.Sleep("2s")
		// Update the page number to get the next page.
		opt.Page = resp.NextPage
	}
	//Update database for project that is no longer in gitlab
	projects := ProjectGet(map[string]string{"where":"1 ORDER BY ts DESC"})
	for _, p := range projects {
		_, _, err := projectService.GetProject(p.Pid, nil)
		if u.CheckNonErrIfMatch(err, "404 Project Not Found", "") != nil {
			p.Delete(nil)
		}
	}
	log.Printf("DumpOrUpdateProject Done\n")
}
func DumpOrUpdateNamespace(git *gitlab.Client, SearchStr string) {
	log.Printf("DumpOrUpdateNamespace Started\n")
	nsService := git.Namespaces
	opt := &gitlab.ListNamespacesOptions{
		Search: gitlab.String(SearchStr),
		ListOptions: gitlab.ListOptions{
			PerPage: 25,
			Page:    1,
		},
	}
	for {
		o, resp, err := nsService.ListNamespaces(opt)
		u.CheckErr(err, "nsService.ListNamespaces")
		for _, row := range o {
			p := GitlabNamespaceNew(row.FullPath)
            lList := []string{}
            if row.Kind == "group"{
                labels, _, err := git.GroupLabels.ListGroupLabels(row.ID, &gitlab.ListGroupLabelsOptions{
                    Page: 1, PerPage: 100,
                })
                u.CheckErr(err, "GroupLabels.ListGroupLabels")
                for _, l := range labels { lList = append(lList, l.Name ) }
            }
			p.Name, p.ParentId, p.Path, p.Kind, p.FullPath, p.MembersCountWithDescendants, p.GitlabNamespaceId, p.Labels = row.Name, row.ParentID, row.Path, row.Kind, row.FullPath, row.MembersCountWithDescendants, row.ID, strings.Join(lList, ",")
			p.Update()
            GitlabGroup2Team(git, &p)
            GitlabGroup2Domain(git, &p)
		}
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		u.Sleep("2s")
		// Update the page number to get the next page.
		opt.Page = resp.NextPage
	}
	log.Printf("DumpOrUpdateNamespace Done\n")
}
//From the team table update its gitlab id. If not found, warning. Maybe in the future we can automate creation of the team.
func UpdateTeam() {
	log.Printf("Update Team Started\n")
	currentTeamList := TeamGet(map[string]string{
		"where": "1",
	})
	for _, row := range currentTeamList {
		ns := GitlabNamespace{}
        //Assume Team Name must be unique. Gitlab group does not require that but it is go1 business rule
		ns.GetOne(map[string]string{
			"where": fmt.Sprintf("name = '%s'", row.Name),
		})
		if ns.ID == 0 {
			log.Printf("[DEBUG] %s\n", u.JsonDump(ns, "    "))
			log.Printf("[ERROR] unextected. Can not find the gitlab namespace table matching this team '%s' with id %d. Possibly the Team has not actually been created in gitlab group.\n", row.Name, row.GitlabNamespaceId)
			continue
		}
		row.GitlabNamespaceId = ns.GitlabNamespaceId
		row.Update()
	}
	log.Printf("Update Team Done\n")
}
//For each group if it started with `Team ` then add a record to team table with data
func GitlabGroup2Team(git *gitlab.Client, ns *GitlabNamespace) {
    if strings.HasPrefix( ns.Name, "Team -" ) {
        log.Printf("[DEBUG] Found gitlab namespace '%s' started with Team. Create - Update Team\n", ns.Name)
        newTeam := TeamNew(ns.Name)
        log.Printf("[DEBUG] %s\n",u.JsonDump(ns, "  "))
        aGroup, _, err := git.Groups.GetGroup(ns.GitlabNamespaceId, nil); u.CheckErr(err, "GitlabGroup2Team Groups.GetGroup")
        newTeam.CreatedAt = aGroup.CreatedAt.Format(u.CleanStringDateLayout)
        newTeam.GitlabNamespaceId = ns.GitlabNamespaceId
        newTeam.Update()
    }
}
//For each group if it started with `Domain ` then add a record to domain table with data
// Maybe we need to check if it has at least a member named started with `Team -` ?
func GitlabGroup2Domain(git *gitlab.Client, ns *GitlabNamespace) {
    if strings.HasPrefix( ns.Name, "Domain -" ) && (ns.MembersCountWithDescendants > 0)  {
        childGroup := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("parent_id = %d AND name LIKE 'Team - %%'", ns.GitlabNamespaceId)})
        newDomain := DomainNew(ns.Name)
        if len(childGroup) > 0 {
            log.Printf("[DEBUG] Found gitlab namespace '%s' started with Domain. Create - Update Domain\n", ns.Name)
            newDomain.HasTeam = 1
        } else {
            newDomain.HasTeam = 0
        }
        aGroup, _, err := git.Groups.GetGroup(ns.GitlabNamespaceId, nil); u.CheckErr(err, "GitlabGroup2Team Groups.GetGroup")
        newDomain.CreatedAt = aGroup.CreatedAt.Format(u.CleanStringDateLayout)
        newDomain.GitlabNamespaceId = ns.GitlabNamespaceId
        newDomain.Update()
    }
}
func GetGitlabClient() *gitlab.Client {
    if GitLabToken = u.Getenv("GITLAB_TOKEN", "-1"); GitLabToken == "-1" {
		if GitLabToken = AppConfig["gitlabToken"].(string); GitLabToken == "changeme" || GitLabToken == "" {
			log.Fatalf("Requires env var GITLAB_TOKEN")
		}
	}
	git, err := gitlab.NewClient(GitLabToken, gitlab.WithBaseURL(AppConfig["gitlabAPIBaseURL"].(string)))
	u.CheckErr(err, "GetGitlabClient NewClient")
    return git
}
func UpdateAllWrapper(git *gitlab.Client, SearchStr string) {
	DumpOrUpdateProject(git, SearchStr)
	DumpOrUpdateNamespace(git, SearchStr)
	UpdateTeam()
	UpdateProjectDomainFromCSV("data/MigrationServices.csv")
	UpdateProjectDomainFromCSVSheet3("data/MigrationServices-sheet3.csv")
	u.RunSystemCommand("rm -rf data/GitlabProject-Domain-Status.xlsx || true; sleep 1; rclone sync onedrive:/GitlabProject-Domain-Status.xlsx data/", false)
	UpdateTeamDomainFromExelNext(git, "data/GitlabProject-Domain-Status.xlsx")
	UpdateProjectDomainFromExcelNext(git, "data/GitlabProject-Domain-Status.xlsx")
	UpdateGroupMember(git)
	UpdateProjectMigrationStatus(git)
}
func main() {
	flag.StringVar(&Logdbpath, "db", "", "db path")
	flag.StringVar(&SearchStr, "s", "", "Project search Str. Empty means everything. If it is a integer then we use as project ID and search for it")
	flag.StringVar(&ConfigFile, "f", "", `Config file. A json file in the format
    {
        "gitlabAPIBaseURL": "https://code.go1.com.au/api/v4",
        "gitlabToken": "changeme",
        "SearchStr": "",
    }`)
	flag.StringVar(&GitLabToken, "tok", "", "GitLabToken if empty then read from env var GITLAB_TOKEN")
	flag.StringVar(&action, "a", "", "Action. Default is update-all. Can be: update-project|update-namespace|update-team|xxx where xxx is the function name")
	flag.Parse()

	ParseConfig()
    git := GetGitlabClient()
	u.ConfigureLogging(os.Stdout)
	SetUpLogDatabase()

	dbc := GetDBConn()
	defer dbc.Close()
	switch action {
	case "update-all":
		UpdateAllWrapper(git, SearchStr)
	case "update-project":
		DumpOrUpdateProject(git, SearchStr)
	case "update-namespace":
		DumpOrUpdateNamespace(git, SearchStr)
        UpdateGroupMember(git)
	case "update-team":
		UpdateTeam()
    //From now is function name - adhoc run
    case "UpdateGroupMember":
        UpdateGroupMember(git)
	case "get-first10mr-peruser":
		Addhoc_getfirst10mrperuser(git)
    case "UpdateProjectDomainFromCSV":
        UpdateProjectDomainFromCSV("data/MigrationServices.csv")
    case "UpdateProjectDomainFromCSVSheet3":
        UpdateProjectDomainFromCSVSheet3("data/MigrationServices-sheet3.csv")
	case "UpdateProjectDomainFromExcelNext":
        u.RunSystemCommand("rm -rf data/GitlabProject-Domain-Status.xlsx || true ; sleep 1; rclone sync onedrive:/GitlabProject-Domain-Status.xlsx data/", true)
		UpdateProjectDomainFromExcelNext(git, "data/GitlabProject-Domain-Status.xlsx")
		UpdateTeamDomainFromExelNext(git, "data/GitlabProject-Domain-Status.xlsx")
	case "UpdateProjectMigrationStatus":
		UpdateProjectMigrationStatus(git)
	case "StartWebGUI":
		StartWebGUI()
	default:
		fmt.Printf("Need an action. Run with -h for help")
	}
}

func ProjectFilter() bool {
	return true
}
