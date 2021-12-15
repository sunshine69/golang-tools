package main

import (
	"log"
	u "localhost.com/utils"
	. "localhost.com/gitlab/model"
	"github.com/xanzy/go-gitlab"
)
//Copy all vars from one group to other if destination does not have the same vars
//Return the list of keys that can not be copied because target exists but having different value
func CopyGroupVars(git *gitlab.Client ,groupA, groupB *gitlab.Group) []*gitlab.GroupVariable {
	gvSrv := git.GroupVariables
	output := []*gitlab.GroupVariable{}
	opt := gitlab.ListGroupVariablesOptions{
		Page: 1,
		PerPage: 100,
	}
	for {
		gVars,resp,err := gvSrv.ListVariables(groupA.ID, &opt); u.CheckErr(err, "CopyGroupVars ListVariables")
		blacklistVarByValue :=  AppConfig["BlacklistVariableValues"].(map[string]interface{})
		for _, gv := range gVars {
			if _, _blOK := blacklistVarByValue[gv.Value]; _blOK {
				log.Printf("[INFO] Value %s is in the blacklist, ignoring...\n", gv.Value)
				continue
			}
			gbv, _, err := gvSrv.GetVariable(groupB.ID, gv.Key, nil)
			if err == nil {
				log.Printf("Target group var key: %s val: %s exists\n", gbv.Key, gbv.Value)
				if gv.Value != gbv.Value {
					log.Printf("[WARNING] Key exists but value are different\n")
					output = append(output, gv)
				} else {
					log.Printf("Value match, skipping")
				}
				continue
			}
			gbv, _, err = gvSrv.CreateVariable(groupB.ID, &gitlab.CreateGroupVariableOptions{
				Key: &gv.Key,
				Value: &gv.Value,
				VariableType: &gv.VariableType,
				EnvironmentScope: &gv.EnvironmentScope,
				Masked: &gv.Masked,
				Protected: &gv.Protected,
			}); u.CheckErr(err, "CopyGroupVars CreateVariable")
			log.Printf("Created new var in group %s\n%s\n", groupB.Name, u.JsonDump(gbv, "  "))
		}
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		// Update the page number to get the next page.
		opt.Page = resp.NextPage
	}
	return output
}
// Copy vars from one project to other. If onlyKeyList is provided then only copy these keys
// otherwise copy all.
// Return list of key that can not be copied because target key exists and having different values
func CopyGroupVarIntoProject(git *gitlab.Client, varList []*gitlab.GroupVariable, p *gitlab.Project) []*gitlab.GroupVariable {
	pvSrv := git.ProjectVariables
	output := []*gitlab.GroupVariable{}
	blacklistVarByValue :=  AppConfig["BlacklistVariableValues"].(map[string]interface{})
	for _, gv := range varList {
		if _, _blOK := blacklistVarByValue[gv.Value]; _blOK {
			log.Printf("[INFO] Value %s is in the blacklist, ignoring...\n", gv.Value)
			continue
		}
		gbv, _, err := pvSrv.GetVariable(p.ID, gv.Key, nil)
		if err == nil {
			log.Printf("Target project var key: %s val: %s exists\n", gbv.Key, gbv.Value)
			if gv.Value != gbv.Value {
				log.Printf("[WARNING] Key exists but value are different\n")
				output = append(output, gv)
			} else {
				log.Printf("Value match, skipping")
			}
			continue
		}
		gbv, _, err = pvSrv.CreateVariable(p.ID, &gitlab.CreateProjectVariableOptions {
			Key: &gv.Key,
			Value: &gv.Value,
			VariableType: &gv.VariableType,
			EnvironmentScope: &gv.EnvironmentScope,
			Masked: &gv.Masked,
			Protected: &gv.Protected,
		}); u.CheckErr(err, "CopyProjectVars CreateVariable")
		log.Printf("Created new var in project %s\n%s\n", p.Name, u.JsonDump(gbv, "  "))
	}
	return output
}
