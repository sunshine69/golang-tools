package main

import (
	"log"
	"strings"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
)
// Per each current project (no matter if it is already created using the new structure), find out its group members and if these group started with Team then pickup its ID and add it here.
//In the mean time if the project path_with_namepsace does not look like it is migrated, set the column domain_ownership_confirm to 0, or 1 otherwise
func UpdateTeamProject(git *gitlab.Client, p *gitlab.Project) {
	pSrv := git.Projects
	opt := &gitlab.ListProjectGroupOptions {
		Search: &SearchStr,
		ListOptions: gitlab.ListOptions{
			Page: 1,
			PerPage: 25,
		},
	}
	for{
		projectGroups, resp, err := pSrv.ListProjectsGroups(p.ID, opt)
		u.CheckErr(err, "pSrv.ListProjectsGroups")
		for _, pg := range projectGroups {
			if strings.HasPrefix(pg.Name, "Team -") {
				tp := TeamProjectNew(uint(pg.ID), uint(p.ID))
				log.Printf("[DEBUG] TeamProjectNew %s\n", u.JsonDump(tp, "  "))
			}
		}
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		u.Sleep("2s")
		opt.Page = resp.NextPage
	}

}
