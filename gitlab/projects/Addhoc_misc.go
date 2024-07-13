package main

import (
	"fmt"
	"log"
	. "localhost.com/gitlab/model"
	u "localhost.com/utils"
	"github.com/xanzy/go-gitlab"
)

// For all adhoc function that is not easy to throw into the test file etc.. This would be called from the cli (main.go)

func DeleteGroup(git *gitlab.Client) {
	fmt.Printf("Enter the group full path to delete:\n")
	var groupPath string
	fmt.Scanf("%s", &groupPath)
	mygroup := GitlabNamespaceNew(groupPath)
	log.Printf("Get group from db: %s\n", u.JsonDump(mygroup, "  "))
	g, _, err := git.Groups.GetGroup(mygroup.GitlabNamespaceId, nil)
	u.CheckErr(err, "DeleteGroup GetGroup")
	log.Printf("YOU ARE GOING TO REMOVE THIS GROUP '%s'. Type YES to continue, otherwise I wont do it.\n", g.FullName)
	var confirm string
    fmt.Scanf("%s", &confirm)
	// rd,_,err := os.Pipe(); t.Fatal(err)
	// saved := os.Stdin
	// os.Stdin = rd
	// scanner := bufio.NewScanner(rd)
	// scanner.Scan()
	// if err := scanner.Err(); err != nil {
	// 	u.CheckErr(err, "")
	// }
	// confirm := scanner.Text()
	// os.Stdin = saved
	if confirm == "YES"{
		fmt.Println("Your answer ", confirm)
		res, err :=  git.Groups.DeleteGroup(g.ID, nil)
		u.CheckErr(err, "DeleteGroup")
		log.Printf("[DEBUG] %s\n", u.JsonDump(res, "  "))
	}
}

func CreateGroup(git *gitlab.Client) {
	fmt.Printf("Enter the group path to create:\n")
	var groupPath string
	fmt.Scanf("%s", &groupPath)
	fmt.Printf("Enter the group parent ID:\n")
	var parentID int
	fmt.Scanf("%d", &parentID)
	lastNewGroup, res, err := git.Groups.CreateGroup(&gitlab.CreateGroupOptions{
		ParentID: &parentID,
		Path:     &groupPath,
		Name:     &groupPath, //Simplify, maybe search replace - with space and Captialize word?
	})
	log.Printf("[DEBUG] response from gitlab to create group path %s with parentID %d - %s\n", groupPath, parentID, u.JsonDump(res, "  "))
	if u.CheckNonErrIfMatch(err, "has already been taken", "") != nil {
		log.Printf("Hit error with 'has already been taken' error obj is: %v\n", err)
		_gs, _, err := git.Groups.ListGroups(&gitlab.ListGroupsOptions{
			Search:     &groupPath,
		})
		u.CheckErr(err, "TransferProject")
		for _, _g := range _gs {
			if _g.ParentID == parentID {
				lastNewGroup = _g
				break
			}
		}
	}
	if err != nil { log.Printf("Hit error obj is: %v\n", err) }
	log.Printf("Output group: %s\n", u.JsonDump(lastNewGroup, "  "))
}