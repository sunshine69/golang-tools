package main

import (
	"log"
	u "localhost.com/utils"
	"github.com/xanzy/go-gitlab"
)
//Copy all vars from one group to other if destination does not have the same vars
func CopyGroupVars(git *gitlab.Client ,groupA, groupB *gitlab.Group) {
	gvSrv := git.GroupVariables
	gVars,_,err := gvSrv.ListVariables(groupA.ID, nil); u.CheckErr(err, "CopyGroupVars ListVariables")
	for _, gv := range gVars {
		gbv, _, err := gvSrv.GetVariable(groupB.ID, gv.Key, nil)
		if err == nil {
			log.Printf("Target group var key: %s val: %s exists\n", gbv.Key, gbv.Value)
			if gv.Value != gbv.Value {
				log.Printf("[WARNING] Key exists but value are different\n")
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
}
