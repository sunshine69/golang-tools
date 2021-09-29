package main

import (
	"log"
	"encoding/csv"
	"os"
	u "localhost.com/utils"
	_ "github.com/mattn/go-sqlite3"
	. "localhost.com/gitlab/model"
)
//This script will update the project - domain but using our new sheet generated. Basically old one based on the sheet of previously AWS-Azure migration. Then we export the result for people to see and adjust/verify
//This final result will be exported to new csv and update using this script.

// As it is new and specific to fit for purpose we don't have to sanitize or hack around names etc. And that is why we put into separate file.

// Read a csv file input and parse it
func UpdateProjectDomainFromCSVNext(filename string) {
	csvFile, err := os.Open(filename); u.CheckErr(err, "UpdateProjectDomainFromCSV OpenCSV file")
	csvReader := csv.NewReader(csvFile)
	if lines, err := csvReader.ReadAll(); err == nil {
		for idx, l := range lines {
			if idx == 0 {continue}
			//project name,path_with_namespace,weburl,domain name
			if l[0] == "" || l[1] == "" || l[2] == ""  { continue }
			p := ProjectNew(l[0])
			if p.Pid == 0 {continue}
			d := DomainNew(l[2])
			if d.GitlabNamespaceId == 0 {continue}
			pd := ProjectDomainNew(p.Pid, d.GitlabNamespaceId)
			log.Printf("[DEBUG] %s\n", u.JsonDump(pd, "  "))
		}
	}
}
