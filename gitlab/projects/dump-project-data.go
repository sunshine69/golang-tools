package main

import (
	"database/sql"
	"strconv"
	"flag"
	"fmt"
	u "localhost.com/utils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
	"log"
	"os"
)
var (
	GitLabToken, projectSearchStr, configFile, Logdbpath string
)

func ParseConfig() map[string]interface{} {
	if configFile == "" {
		log.Fatalf("Config file required. Run with -h for help")
	}
	config := u.ParseConfig(configFile)
	if projectSearchStr == "" && config["projectSearchStr"].(string) != "" {
		projectSearchStr = config["projectSearchStr"].(string)
	}
	return config
}
func main() {
	flag.StringVar(&Logdbpath, "db", "", "db path")
	flag.StringVar(&projectSearchStr, "s", "", "Project search Str. Empty means everything. If it is a integer then we use as project ID and search for it")
	flag.StringVar(&configFile, "f", "", `Config file. A json file in the format
	{
		"gitlabAPIBaseURL": "https://code.go1.com.au/api/v4",
		"gitlabToken": "changeme",
		"projectSearchStr": "",
	}`)
	flag.StringVar(&GitLabToken, "tok", "", "GitLabToken if empty then read from env var GITLAB_TOKEN")
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
	opt := &gitlab.ListProjectsOptions{
		Search: gitlab.String(projectSearchStr),
		ListOptions: gitlab.ListOptions{
			PerPage: 25,
			Page:    1,
		},
	}
	projectService := git.Projects
	dbc := GetDBConn()
	defer dbc.Close()

	insert_stmt, err := dbc.Prepare(`INSERT INTO project(pid, weburl, owner_id, owner_name, name, name_with_space, path, path_with_namespace, namespace_kind, namespace_name, namespace_id, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	u.CheckErr(err, "Prepare")
	defer insert_stmt.Close()

	for {
		var (
			projects []*gitlab.Project
			project *gitlab.Project
			resp *gitlab.Response
			err error
		)
		projectID, err := strconv.Atoi(projectSearchStr)
		if err == nil {
			project, resp, err = projectService.GetProject(projectID, nil)
			u.CheckErr(err, "GetProject")
			projects = []*gitlab.Project{ project }
		} else {
			projects, resp, err = projectService.ListProjects(opt)
			u.CheckErr(err, "Projects.ListProjects")
		}
		var owner_id int
		var owner_name string
		for _, row := range projects {
			log.Printf("[DEBUG] %s\n", u.JsonDump(row, "    "))
			// if ! row.ContainerRegistryEnabled {
			// 	continue
			// }
			if ProjectFilter() {
				fmt.Printf("Project %s - \n", u.JsonDump(row, "    "))
				if row.Owner != nil {
					owner_id = row.Owner.ID
					owner_name = row.Owner.Name
				} else {
					owner_id = -1
					owner_name = "null"
				}
				// namespace_kind text, namespace_name text, namespace_id
				_, err = insert_stmt.Exec( row.ID, row.WebURL, owner_id,
				owner_name, row.Name, row.NameWithNamespace,
				row.Path, row.PathWithNamespace, row.Namespace.Kind, row.Namespace.Name, row.Namespace.ID, row.CreatedAt )
				u.CheckErr(err, "insert_stmt.Exec")
			}
		}
		// Exit the loop when we've seen all pages.
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		u.Sleep("3s")
		// Update the page number to get the next page.
		opt.Page = resp.NextPage
	}
}
func ProjectFilter() bool {
	return true
}

func SetUpLogDatabase() {
	conn := GetDBConn()
	defer conn.Close()
	sql := `
	--drop table log;
	CREATE TABLE IF NOT EXISTS project(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pid int, weburl text, owner_id int, owner_name text, name text, name_with_space text, path text, path_with_namespace text, namespace_kind text, namespace_name text, namespace_id int, created_at DATETIME);

	CREATE INDEX IF NOT EXISTS log_ts ON project(pid);

	create table IF NOT EXISTS team (id INTEGER PRIMARY KEY AUTOINCREMENT, name text);
	create table IF NOT EXISTS team_project(id INTEGER PRIMARY KEY AUTOINCREMENT, team_id int, project_id int, domain text);

	PRAGMA main.page_size = 4096;
	PRAGMA main.cache_size=10000;
	PRAGMA main.locking_mode=EXCLUSIVE;
	PRAGMA main.synchronous=NORMAL;
	PRAGMA main.journal_mode=WAL;
	PRAGMA main.cache_size=5000;`
	log.Printf("[INFO] Set up database schema\n")
	_, err := conn.Exec(sql)
	if err != nil {
		panic(err)
	}
}
//GetDBConn -
func GetDBConn() *sql.DB {
	db, err := sql.Open("sqlite3", Logdbpath)
	if err != nil {
		panic(err)
	}
	if db == nil {
		panic("db nil")
	}
	return db
}
