package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	u "localhost.com/utils"

	// gu "localhost.com/gitlab/utils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
)
//Started from a Domain. List all sub domains and project associated. If the domain is new one (found in domain table) then these projects has been migrated.
func ReportProjectMigrationStatus(git *gitlab.Client) {
	output := []string{"created_at,close_at,author_id,author,title,project"}
	MergeReqService := git.MergeRequests
	UsersService := git.Users
	activeOpt := true
	scope := "all"
	uOpt := &gitlab.ListUsersOptions{
		Active: &activeOpt,
		ListOptions: gitlab.ListOptions{
			Page:    1,
			PerPage: 25,
		},
	}
	for {
		users, resp, err := UsersService.ListUsers(uOpt)
		u.CheckErr(err, "UsersService.ListUsers")
		for _, user := range users {
			log.Printf("[DEBUG] Set option to list MR for user %s ID %d\n", user.Name, user.ID)
			opt := &gitlab.ListMergeRequestsOptions{
				AuthorID: &user.ID,
				Scope:    &scope,
				ListOptions: gitlab.ListOptions{
					Page:    1,
					PerPage: 10,
				},
			}
			mrList, _, err := MergeReqService.ListMergeRequests(opt)
			u.CheckErr(err, "MergeReqService.ListMergeRequests")
			for _, mr := range mrList {
				create_at, close_at := "", ""
				if mr.CreatedAt != nil {
					create_at = mr.CreatedAt.Format(u.AUTimeLayout)
				}
				if mr.ClosedAt != nil {
					close_at = mr.ClosedAt.Format(u.AUTimeLayout)
				}
				project, _, _ := git.Projects.GetProject(mr.ProjectID, nil)

				line := fmt.Sprintf("%s,%s,%d,%s,%s,%s", create_at, close_at, user.ID, user.Name, mr.Title, project.Name)
				output = append(output, line)
				fmt.Printf("%s\n%s\n", u.JsonDump(user, "  "), line)
			}
		}
		if resp.CurrentPage >= resp.TotalPages {
			fmt.Printf("Break %s %s\n", u.JsonDump(resp, "  "), u.JsonDump(uOpt, "  "))
			break
		}
		u.Sleep("2s")
		uOpt.Page = resp.NextPage
	}
	data := strings.Join(output, "\n")
	ioutil.WriteFile("Addhoc_getfirst10mrperuser.csv", []byte(data), 0777)
}
