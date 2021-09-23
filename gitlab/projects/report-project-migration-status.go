package main

import (
	// "fmt"
	// "io/ioutil"
	// // "log"
	// "strings"
	// . "localhost.com/gitlab/model"
	// u "localhost.com/utils"
	// gu "localhost.com/gitlab/utils"
	// _ "github.com/mattn/go-sqlite3"
	// "github.com/xanzy/go-gitlab"
)
//Started from a Domain. List all sub domains and project associated. If the domain is new one (found in domain table) then these projects has been migrated.
// func ReportProjectMigrationStatus() {
// 	output := []string{"created_at,close_at,author_id,author,title,project"}
// 	// sql := `select p.path_with_namespace, p.weburl, ns.name from project as p, gitlab_namespace as ns where p.namespace_id = ns.gitlab_ns_id and ns.name like 'Domain - %';`
// 	dbc := GetDBConn(); defer dbc.Close()
// 	domains := GitlabNamespaceGet(map[string]string{"where": fmt.Sprintf("name LIKE 'Domain - %%'")})
// 	for _, row := range domains {
// 		if row.ParentId == 0 {//Root group, no parent
// 			if row.MembersCountWithDescendants > 0 {//Having a subgroup or project/domain
// 				//Find projects
// 				ps := ProjectGet(map[string]string{"where": fmt.Sprintf("namespace_id = %d", row.GitlabNamespaceId)})
// 				for _, p := range ps {

// 				}
// 			}
// 		}
// 	}
// 	data := strings.Join(output, "\n")
// 	ioutil.WriteFile("Addhoc_getfirst10mrperuser.csv", []byte(data), 0777)
// }
