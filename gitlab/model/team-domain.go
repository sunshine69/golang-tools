package model

import (
	"fmt"
	"log"
	"strings"
	"github.com/sunshine69/sqlstruct"
	u "localhost.com/utils"
)

type TeamDomain struct {
	ID                  uint   `sql:"id"`
	TeamId              uint `sql:"team_id"`
	DomainId           uint `sql:"domain_id"`
}
func (p *TeamDomain) GetOrNew(team_id, domain_id uint) {
	p.GetOne(map[string]uint{"team_id": team_id, "domain_id": domain_id})
	if p.ID == 0 {
		p.New(team_id, domain_id, false)
	}
}
func (p *TeamDomain) GetOne(inputmap map[string]uint) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team_domain WHERE id = %d`, sqlstruct.Columns(TeamDomain{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM team_domain WHERE team_id = %d AND domain_id = %d`, sqlstruct.Columns(TeamDomain{}), inputmap["team_id"], inputmap["domain_id"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "TeamDomain GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "TeamDomain GetOne query")
	}
}
func (p *TeamDomain) Get(inputmap map[string]string) []TeamDomain {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team_domain WHERE id = %s`, sqlstruct.Columns(TeamDomain{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM team_domain WHERE %s`, sqlstruct.Columns(TeamDomain{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "TeamDomain GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []TeamDomain{}
	for rows.Next() {
		localp := TeamDomain{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "TeamDomain Get query")
		o = append(o, localp)
	}
	return o
}
func (p *TeamDomain) New(team_id, domain_id uint, update bool) {
	p.TeamId, p.DomainId= team_id, domain_id
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New TeamDomain dbc.Begin")
	sql := `INSERT INTO team_domain(team_id, domain_id) VALUES(?, ?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New TeamDomain")
	defer stmt.Close()
	log.Printf("[DEBUG] sql - %s - param '%d', '%d'\n", sql, team_id, domain_id)
	res, err := stmt.Exec(team_id, domain_id); u.CheckErr(err, "New teamname stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = uint(_ID)
	tx.Commit()
	if update {
		p.Update()
	}
}
func (p *TeamDomain) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "TeamDomain dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(TeamDomain{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE team_domain SET %s = ? WHERE id = ?`, colname)
		stmt, err := tx.Prepare(sql)
		u.CheckErr(err, "tx.Prepare")
		defer stmt.Close()
		switch colname {
		case "id", "team_id", "domain_id":
			continue
		default:
			fmt.Println("Not matching anything.")
		}
	}
	u.CheckErr(tx.Commit(), "tx.Commit")
}
func (p *TeamDomain) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM team_domain WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM team_domain WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM team_domain WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "TeamDomain dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "TeamDomain Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "TeamDomain Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
