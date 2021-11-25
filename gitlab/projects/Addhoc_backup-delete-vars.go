package main

import (
	"fmt"
	"log"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"

	// gu "localhost.com/gitlab/utils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xanzy/go-gitlab"
)
// Search all vars globally and if match the value then back it up in a way we can restore it later on if needed. Then delete it
func Addhoc_backup_delete_vars_by_value(git *gitlab.Client, value string) {
	sqlwhere := fmt.Sprintf(`namespace_kind = 'group' AND labels NOT LIKE '%%personal%%' AND is_active = 1 ORDER BY ts`)
	// Project vars
	projects := ProjectGet(map[string]string{"where": sqlwhere})
	for _, p := range projects {
		// gproject, _, err := git.Projects.GetProject(p.Pid, nil)
		pvars, _, err := git.ProjectVariables.ListVariables(p.Pid, nil)
		if u.CheckErrNonFatal(err, "Addhoc_backup_delete_vars_by_value GetProject") != nil {
			continue
		}
		for _, pv := range pvars {
			if pv.Value == value {
				log.Printf("[DEBUG] Found var to be deleted - %s\n", u.JsonDump(pv, "  "))
				application := fmt.Sprintf(`{"key": "%s", "value": "%s", "pid": %d, "gid": %d}`, pv.Key, pv.Value, p.Pid, 0)
				evtlog := EventLogNew(u.JsonDump(pv, "  "))
				evtlog.Application = application
				evtlog.Update()
				_, err := git.ProjectVariables.RemoveVariable(p.Pid, pv.Key, nil)
				u.CheckErr(err, "Addhoc_backup_delete_vars_by_value RemoveVariable")
			}
		}
	}
	// Domain group vars
	groups := GitlabNamespaceGet(map[string]string{"where": "kind = 'group'"})
	for _, g := range groups {
		gvars, _, err := git.GroupVariables.ListVariables(g.GitlabNamespaceId, nil)
		if u.CheckErrNonFatal(err, "Addhoc_backup_delete_vars_by_value GroupVariables.ListVariables") != nil {
			continue
		}
		for _, gv := range gvars {
			if gv.Value == value {
				log.Printf("[DEBUG] Found var to be deleted - %s\n", u.JsonDump(gv, "  "))
				application := fmt.Sprintf(`{"key": "%s", "value": "%s", "pid": %d, "gid": %d}`, gv.Key, gv.Value, 0, g.GitlabNamespaceId)
				evtlog := EventLogNew(u.JsonDump(gv, "  "))
				evtlog.Application = application
				evtlog.Update()
				_, err := git.GroupVariables.RemoveVariable(g.GitlabNamespaceId, gv.Key, nil)
				u.CheckErr(err, "Addhoc_backup_delete_vars_by_value RemoveVariable")
			}
		}
	}
}