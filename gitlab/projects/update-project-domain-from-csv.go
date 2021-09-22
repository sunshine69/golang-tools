package main

import (
	"fmt"
	"strings"
	"encoding/csv"
	"os"
	u "localhost.com/utils"
	_ "github.com/mattn/go-sqlite3"
	. "localhost.com/gitlab/model"
)
//Make it sane again
func Sanitize(pName string) string {
	o := strings.ReplaceAll(pName, "-prod", "")
	return o
}
//Give a name, get one project best match
func GetAProjectSmartly(pName string) Project {
	p := Project{}
	p.GetOne(map[string]string{
		"where": fmt.Sprintf(""),
	})
	return p
}
// Read a csv file input and parse it
func UpdateProjectDomainFromCSV(filename string) {
	csvFile, err := os.Open(filename); u.CheckErr(err, "UpdateProjectDomainFromCSV OpenCSV file")
	csvReader := csv.NewReader(csvFile)
	if lines, err := csvReader.ReadAll(); err == nil {
		for idx, l := range lines {
			if idx == 0 {continue}
			//Service Name,Migration status,Type,QA,Domain,Ready for QA,Notes,Azure url,Running in Azure,Configuration Correct,E2E testing completed,Tech Lead Review,Old Team Name,Previous Feature Team
			if l[0] == "" || l[4] == "" { continue }
			// projectNameKW := Sanitize(l[0])
		}
	}

}
