package model

import (
	"fmt"
	"log"
	"strings"

	"github.com/sunshine69/sqlstruct"
	u "localhost.com/utils"
)

type Team struct {
	ID                uint   `sql:"id"`
	Name              string `sql:"name"`
	Keyword           string `sql:"keyword"`
	Note              string `sql:"note"`
	GitlabNamespaceId int    `sql:"gitlab_ns_id"`
}
func (p *Team) GetOneOrNew(name string) {
	p.GetOne(map[string]string{"where": fmt.Sprintf("name = '%s'", name)})
	if p.ID == 0 {
		p.New(name, false)
		//Update struct with database default value
		p.GetOne(map[string]string{"id": fmt.Sprintf("%d", p.ID)})
	}
}
func (p *Team) GetOne(inputmap map[string]string) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team WHERE id = %s`, sqlstruct.Columns(Team{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM team WHERE %s`, sqlstruct.Columns(Team{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "Team GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "Team GetOne query")
	}
}
func (p *Team) Get(inputmap map[string]string) []Team {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team WHERE id = %s`, sqlstruct.Columns(Team{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM team WHERE %s`, sqlstruct.Columns(Team{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "Team GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []Team{}
	for rows.Next() {
		localp := Team{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "Team Get query")
		o = append(o, localp)
	}
	return o
}
func (p *Team) New(teamname string, update bool) {
	p.Name = teamname
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New teamname dbc.Begin")
	sql := `INSERT INTO team(name) VALUES(?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New teamname")
	defer stmt.Close()
	log.Printf("[DEBUG] sql - %s - param '%s'\n", sql, teamname)
	res, err := stmt.Exec(teamname); u.CheckErr(err, "New teamname stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = uint(_ID)
	tx.Commit()
	if update {
		p.Update()
	}
}
func (p *Team) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(Team{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE team SET %s = ? WHERE id = ?`, colname)
		stmt, err := tx.Prepare(sql)
		u.CheckErr(err, "tx.Prepare")
		defer stmt.Close()
		switch colname {
		case "id":
			continue
		case "name":
			_, err := stmt.Exec(p.Name, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "keyword":
			_, err = stmt.Exec(p.Keyword, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "note":
			_, err = stmt.Exec(p.Note, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "gitlab_ns_id":
			_, err = stmt.Exec(p.GitlabNamespaceId, p.ID)
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
func (p *Team) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM team WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM team WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM team WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "Team dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "Team Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "Team Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
