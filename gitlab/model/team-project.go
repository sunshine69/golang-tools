package model

import (
	"fmt"
	"log"
	"strings"

	"github.com/sunshine69/sqlstruct"
	u "localhost.com/utils"
)

type TeamProject struct {
	ID                  uint   `sql:"id"`
	TeamId              uint `sql:"team_id"`
	ProjectId           uint `sql:"project_id"`
	Domain              string `sql:"domain"`
}
func (p *TeamProject) GetOrNew(team_id, project_id uint) {
	p.GetOne(map[string]uint{"team_id": team_id, "project_id": project_id})
	if p.ID == 0 {
		p.New(team_id, project_id, false)
	}
}
func (p *TeamProject) GetOne(inputmap map[string]uint) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team_project WHERE id = %d`, sqlstruct.Columns(TeamProject{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM team_project WHERE team_id = %d AND project_id = %d`, sqlstruct.Columns(TeamProject{}), inputmap["team_id"], inputmap["project_id"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "TeamProject GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "TeamProject GetOne query")
	}
}
func (p *TeamProject) Get(inputmap map[string]string) []TeamProject {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team_project WHERE id = %s`, sqlstruct.Columns(TeamProject{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM team_project WHERE %s`, sqlstruct.Columns(TeamProject{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "TeamProjectGetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []TeamProject{}
	for rows.Next() {
		localp := TeamProject{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "TeamProjectGet query")
		o = append(o, localp)
	}
	return o
}
func (p *TeamProject) New(team_id, project_id uint, update bool) {
	p.TeamId, p.ProjectId, p.Domain = team_id, project_id, ""
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New TeamProject dbc.Begin")
	sql := `INSERT INTO team_project(team_id, project_id) VALUES(?, ?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New TeamProject")
	defer stmt.Close()
	log.Printf("[DEBUG] sql - %s - param '%d', '%d'\n", sql, team_id, project_id)
	res, err := stmt.Exec(team_id, project_id); u.CheckErr(err, "New teamname stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = uint(_ID)
	tx.Commit()
	if update {
		p.Update()
	}
}
func (p *TeamProject) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "TeamProject dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(TeamProject{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE team_project SET %s = ? WHERE id = ?`, colname)
		stmt, err := tx.Prepare(sql)
		u.CheckErr(err, "tx.Prepare")
		defer stmt.Close()
		switch colname {
		case "id", "team_id", "project_id":
			continue
		case "domain":
			_, err := stmt.Exec(p.Domain, p.ID)
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
func (p *TeamProject) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM team_project WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM team_project WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM team_project WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "TeamProject dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "TeamProject Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "TeamProject Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
