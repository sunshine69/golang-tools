package model

import (
	"fmt"
	"log"
	"strings"
	"github.com/sunshine69/sqlstruct"
	u "localhost.com/utils"
)

type ProjectDomain struct {
	ID                  int  `sql:"id"`
	ProjectId           int `sql:"project_id"`
	DomainId            int `sql:"domain_id"`
	TS         string   `sql:"ts"`
}
func ProjectDomainNew(project_id, domain_id int) ProjectDomain {
	p := ProjectDomain{}
	p.GetOne(map[string]int{"project_id": project_id, "domain_id": domain_id})
	if p.ID == 0 {
		p.New(project_id, domain_id, false)
	}
	return p
}
func (p *ProjectDomain) GetOne(inputmap map[string]int) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM project_domain WHERE id = %d`, sqlstruct.Columns(ProjectDomain{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM project_domain WHERE project_id = %d AND domain_id = %d`, sqlstruct.Columns(ProjectDomain{}), inputmap["project_id"], inputmap["domain_id"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "ProjectDomain GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "ProjectDomain GetOne query")
	}
}
func ProjectDomainGet(inputmap map[string]string) []ProjectDomain {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM project_domain WHERE id = %s`, sqlstruct.Columns(ProjectDomain{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM project_domain WHERE %s`, sqlstruct.Columns(ProjectDomain{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "ProjectDomain GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []ProjectDomain{}
	for rows.Next() {
		localp := ProjectDomain{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "ProjectDomain Get query")
		o = append(o, localp)
	}
	return o
}
func (p *ProjectDomain) New(project_id, domain_id int, update bool) {
	p.ProjectId, p.DomainId= project_id, domain_id
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New ProjectDomain dbc.Begin")
	sql := `INSERT INTO project_domain(project_id, domain_id) VALUES(?, ?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New ProjectDomain")
	defer stmt.Close()
	log.Printf("[DEBUG] sql - %s - param '%d', '%d'\n", sql, project_id, domain_id)
	res, err := stmt.Exec(project_id, domain_id); u.CheckErr(err, "New teamname stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = int(_ID)
	tx.Commit()
	if update {
		p.Update()
	}
}
func (p *ProjectDomain) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "ProjectDomain dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(ProjectDomain{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE project_domain SET %s = ? WHERE id = ?`, colname)
		stmt, err := tx.Prepare(sql)
		u.CheckErr(err, "tx.Prepare")
		defer stmt.Close()
		switch colname {
		case "id", "project_id", "domain_id":
			continue
		case "ts":
			_, err := stmt.Exec("", p.ID) //Just update so trigger will fired to udpate ts
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		default:
			fmt.Println("Not matching anything.")
		}
	}
	u.CheckErr(tx.Commit(), "tx.Commit")
}
func (p *ProjectDomain) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM project_domain WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM project_domain WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM project_domain WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "ProjectDomain dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "ProjectDomain Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "ProjectDomain Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
