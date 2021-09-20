package main

import (
    "fmt"
    "log"
    "strings"
    "database/sql"
    "strconv"
    "flag"
    u "localhost.com/utils"
    // gu "localhost.com/gitlab/utils"
    _ "github.com/mattn/go-sqlite3"
    "github.com/xanzy/go-gitlab"
    "os"
)
var (
    GitLabToken, SearchStr, configFile, Logdbpath, action string
)
func ParseConfig() map[string]interface{} {
    if configFile == "" {
        log.Fatalf("Config file required. Run with -h for help")
    }
    config := u.ParseConfig(configFile)
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
            project *gitlab.Project
            resp *gitlab.Response
            err error
        )
        projectID, err := strconv.Atoi(SearchStr)
        if err == nil {
            project, resp, err = projectService.GetProject(projectID, nil)
            u.CheckErr(err, "GetProject")
            projects = []*gitlab.Project{ project }
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
	opt := &gitlab.ListNamespacesOptions {
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
            p.Name, p.ParentId, p.Path,  p.Kind,  p.FullPath, p.MembersCountWithDescendants, p.GitlabNamespaceId = row.Name, uint(row.ParentID), row.Path, row.Kind, row.FullPath, uint(row.MembersCountWithDescendants), uint(row.ID)
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
    flag.StringVar(&configFile, "f", "", `Config file. A json file in the format
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

func SetUpLogDatabase() {
    conn := GetDBConn()
    defer conn.Close()
    sql := `
    CREATE TABLE IF NOT EXISTS project (
        "id"    INTEGER,
        "pid"   int,
        "weburl"    text,
        "owner_id"  int,
        "owner_name"    text,
        "name"  text,
        "name_with_space"   text,
        "path"  text,
        "path_with_namespace"   text UNIQUE,
        "namespace_kind"    text,
        "namespace_name"    text,
        "namespace_id"  int,
        "tag_list"  text,
        "gitlab_created_at" DATETIME,
        "is_active" INTEGER DEFAULT 1,
        "domain_ownership_confirmed"    INTEGER DEFAULT 0,
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE INDEX IF NOT EXISTS pid_idx ON project(pid);

    CREATE TABLE IF NOT EXISTS "gitlab_namespace" (
        "id"	INTEGER,
        "name"	TEXT,
        "parent_id"	INTEGER,
        "path"	TEXT,
        "kind"	TEXT,
        "full_path"	TEXT UNIQUE,
        "members_count_with_descendants"	INTEGER,
        "gitlab_ns_id"	INTEGER,
        "domain_ownership_confirmed"	INTEGER DEFAULT 0,
        "web_url"	TEXT,
        "avatar_url"	TEXT,
        "billable_members_count"	INTEGER,
        "seats_in_use"	INTEGER,
        "max_seats_used"	INTEGER,
        "plan"	TEXT,
        "trial_ends_on"	TEXT,
        "trial"	INTEGER DEFAULT 0,
        PRIMARY KEY("id" AUTOINCREMENT)
    );

    CREATE TABLE IF NOT EXISTS team (
        "id"    INTEGER,
        "name"  text,
        "keyword"   TEXT,
        "note"  TEXT,
        "gitlab_ns_id"  INTEGER DEFAULT -1,
        PRIMARY KEY("id" AUTOINCREMENT)
    );

    CREATE TABLE IF NOT EXISTS team_project(id INTEGER PRIMARY KEY AUTOINCREMENT, team_id int, project_id int, domain text);

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
