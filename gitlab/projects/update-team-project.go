package main

import (
	"fmt"
	"log"
	"strings"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
	"github.com/xuri/excelize/v2"
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
				tp := TeamProjectNew(pg.ID, p.ID)
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
func UpdateTeamProjectFromExelNext(git *gitlab.Client, filename string) {
	f, err := excelize.OpenFile(filename)
	u.CheckErr(err, "UpdateTeamProjectFromExelNext OpenFile")
	lines, err := f.GetRows("Team"); u.CheckErr(err, "UpdateTeamProjectFromExelNext GetRows")
	for idx, l := range lines {
		if idx == 0 {continue}
		UpdateTeamOneRow(git, idx, l)
	}
	lines, err = f.GetRows("Project_Team"); u.CheckErr(err, "UpdateTeamProjectFromExelNext GetRows")
	for idx, l := range lines {
		if idx == 0 {continue}
		UpdateTeamProjectOneRow(git, idx, l)
	}
}
func UpdateTeamProjectOneRow(git *gitlab.Client, idx int, l []string) *TeamProject {
	if len(l) < 4 { return nil }
	//3 - access-level   1 - path_with_namespace  2 - team name. 0 - project name but not used
	if l[3] == "" || l[1] == "" || l[2] == ""  { return nil }
	ts := TeamGet(map[string]string{"where":fmt.Sprintf("name = '%s'", l[2])})
	if ! u.Assert(len(ts) == 1, "Team should exists in Team table", false) { return nil }
	ps := ProjectGet(map[string]string{"where":fmt.Sprintf("path_with_namespace = '%s'", l[1])})
	if ! u.Assert(len(ps) == 1, "Project should exists in Project table", false) {return nil}
	tp := TeamProjectNew(ts[0].GitlabNamespaceId, ps[0].Pid)
	tp.Permission = l[3]
	tp.Update()
	log.Printf("[DEBUG] %s\n", u.JsonDump(tp, "  "))
	AddGitlabTeamToProject(git, &ps[0])
	return &tp
}
func AddGitlabTeamToProject(git *gitlab.Client, p *Project) {
	tps := TeamProjectGet(map[string]string{"where": fmt.Sprintf("project_id = %d", p.Pid)})
	for _, teamp := range tps {
		_, err := git.Projects.ShareProjectWithGroup(p.Pid, &gitlab.ShareWithGroupOptions{
			GroupID: &teamp.TeamId,
			GroupAccess: gitlab.AccessLevel(GitlabPermissionLookup[teamp.Permission]),
		})
		u.CheckErrNonFatal(err, fmt.Sprintf("AddGitlabTeamToProject - %s\n", u.JsonDump(teamp, "  ")) )
	}
}