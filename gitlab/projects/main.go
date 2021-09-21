package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"

	. "localhost.com/gitlab/model"
	u "localhost.com/utils"

	// gu "localhost.com/gitlab/utils"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
)

var (
    action string
)

func ParseConfig() map[string]interface{} {
	if ConfigFile == "" {
		log.Fatalf("Config file required. Run with -h for help")
	}
	config := u.ParseConfig(ConfigFile)
	if SearchStr == "" && config["SearchStr"].(string) != "" {
		SearchStr = config["SearchStr"].(string)
	}
	return config
}
func DumpOrUpdateProject(git *gitlab.Client, SearchStr string) {
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
				p := Project{}
				p.GetOne(map[string]string{
					"where": fmt.Sprintf("path_with_namespace = '%s'", row.PathWithNamespace),
				})
				if p.ID == 0 {
					log.Printf("[INFO] Creating new project with Name: %s - ID %d - PathWithNamespace %s\n", row.Name, row.ID, row.PathWithNamespace)
					p.New(row.PathWithNamespace, false)
				}
				log.Printf("[DEBUG] Project %s - \n", u.JsonDump(p, "    "))
				if row.Owner != nil {
					p.OwnerId = row.Owner.ID
					p.OwnerName = row.Owner.Name
				} else {
					p.OwnerId = -1
					p.OwnerName = "null"
				}
				p.TagList = strings.Join(row.Topics, ",")
				p.Pid, p.Weburl, p.Name, p.NameWithSpace, p.Path, p.PathWithNamespace, p.NamespaceKind, p.NamespaceName, p.NamespaceId, p.GitlabCreatedAt = uint(row.ID), row.WebURL, row.Name, row.NameWithNamespace, row.Path, row.PathWithNamespace, row.Namespace.Kind, row.Namespace.Name, row.Namespace.ID, row.CreatedAt.Format(u.CleanStringDateLayout)
				p.Update()
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
}
func DumpOrUpdateNamespace(git *gitlab.Client, SearchStr string) {
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
			p := GitlabNamespace{}
			p.GetOne(map[string]string{
				"where": fmt.Sprintf("full_path = '%s'", row.FullPath),
			})
			if p.ID == 0 {
				p.New(row.FullPath, false)
			}
			p.Name, p.ParentId, p.Path, p.Kind, p.FullPath, p.MembersCountWithDescendants, p.GitlabNamespaceId = row.Name, uint(row.ParentID), row.Path, row.Kind, row.FullPath, uint(row.MembersCountWithDescendants), uint(row.ID)
			p.Update()
		}

		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		u.Sleep("2s")
		// Update the page number to get the next page.
		opt.Page = resp.NextPage
	}
}

func UpdateTeam() {
	ateam := Team{}
	currentTeamList := ateam.Get(map[string]string{
		"where": "1",
	})
	for _, row := range currentTeamList {
		ns := GitlabNamespace{}
		ns.GetOne(map[string]string{
			"where": fmt.Sprintf("name = '%s'", row.Name),
		})
		if ns.ID == 0 {
			log.Printf("[DEBUG] %s\n", u.JsonDump(ns, "    "))
			log.Printf("[WARN] unextected. Can not find the gitlab namespace table matching this team '%s' with id %d. Possibly the Team has not actually been created in gtilab group.\n", row.Name, row.GitlabNamespaceId)
			continue
		}
		row.GitlabNamespaceId = int(ns.GitlabNamespaceId)
		row.Update()
	}
}
func UpdateTeamProject() {

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

	config := ParseConfig()
	u.ConfigureLogging(os.Stdout)
	SetUpLogDatabase()

	if GitLabToken = u.Getenv("GITLAB_TOKEN", "-1"); GitLabToken == "-1" {
		if GitLabToken = config["gitlabToken"].(string); GitLabToken == "changeme" || GitLabToken == "" {
			log.Fatalf("Requires env var GITLAB_TOKEN")
		}
	}
	git, err := gitlab.NewClient(GitLabToken, gitlab.WithBaseURL(config["gitlabAPIBaseURL"].(string)))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	dbc := GetDBConn()
	defer dbc.Close()
	switch action {
	case "update-all":
		DumpOrUpdateProject(git, SearchStr)
		DumpOrUpdateNamespace(git, SearchStr)
		UpdateTeam()
	case "update-project":
		DumpOrUpdateProject(git, SearchStr)
	case "update-namespace":
		DumpOrUpdateNamespace(git, SearchStr)
	case "update-team":
		UpdateTeam()
	case "get-first10mr-peruser":
		Addhoc_getfirst10mrperuser(git)
	default:
		fmt.Printf("Need an action. Run with -h for help")
	}
}

func ProjectFilter() bool {
	return true
}
