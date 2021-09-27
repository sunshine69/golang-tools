package main

// import (
// 	"log"
// 	"strings"
// 	u "localhost.com/utils"
// 	. "localhost.com/gitlab/model"
// 	_ "github.com/mattn/go-sqlite3"
// 	"github.com/xanzy/go-gitlab"
// )
// Take a project_id and automate the transfer process. This should be run on a dashboard manually per project
// - Assign to new domain/team using gitlab API
// - Trigger a build of the new project with the last release state
// - Check and in theory manual qa and prod deploy should work and prod deploy as well
// - Remove the fork relationtionship of the new project to make it independent (if we use the fork model)

// This is run after we get all information for Team_Domain, Project_Domain manually updated by hand using spreadsheet. Project_Domain handled by UpdateProjectDomainFromCSVNext. Team_Domain by

// func TransferProject(git *gitlab.Client, gitlabProjectId int) {
// 	gitlabProject, _, err := git.Projects.GetProject(gitlabProjectId, nil)
// 	u.CheckErr(err, "TransferProject Projects.GetProject")

// 	for{
// 		projectGroups, resp, err := pSrv.ListProjectsGroups(p.ID, opt)
// 		u.CheckErr(err, "pSrv.ListProjectsGroups")
// 		for _, pg := range projectGroups {
// 			if strings.HasPrefix(pg.Name, "Team -") {
// 				tp := TeamProjectNew(pg.ID, p.ID)
// 				log.Printf("[DEBUG] TeamProjectNew %s\n", u.JsonDump(tp, "  "))
// 			}
// 		}
// 		if resp.CurrentPage >= resp.TotalPages {
// 			break
// 		}
// 		u.Sleep("2s")
// 		opt.Page = resp.NextPage
// 	}

// }
