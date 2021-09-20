package gitlabutils

import (
	"fmt"
	u "localhost.com/utils"
	"github.com/xanzy/go-gitlab"

)

func GetNameSpace(git *gitlab.Client, searchStr string) {
	nsService := git.Namespaces
	listNsOpt := &gitlab.ListNamespacesOptions {
		Search: gitlab.String(searchStr),
		ListOptions: gitlab.ListOptions{
			PerPage: 25,
			Page:    1,
		},
	}
	o, _, err := nsService.ListNamespaces(listNsOpt)
	u.CheckErr(err, "nsService.ListNamespaces")
	fmt.Printf("%s\n", u.JsonDump(o, "    ") )
}
