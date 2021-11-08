package model

import (
	"fmt"
	"log"
	"strings"
	"github.com/sunshine69/sqlstruct"
	u "github.com/sunshine69/golang-tools/utils"
)

type TeamUser struct {
	ID                  int    	`sql:"id"`
	TS         			string  `sql:"ts"`
	TeamId              int    	`sql:"team_id"`
	UserId              int 	`sql:"user_id"`
	Max_role          string 	`sql:"max_role"`
	Access_expires string `sql:"access_expires"`
	Source string `sql:"source"`
	Expiration string `sql:"expiration"`
	Access_granted string `sql:"access_granted"`
}
func TeamUserNew(team_id, user_id int) TeamUser {
	p := TeamUser{}
	p.GetOne(map[string]int{"team_id": team_id, "user_id": user_id})
	if p.ID == 0 {
		p.New(team_id, user_id, false)
	}
	return p
}
func (p *TeamUser) GetOne(inputmap map[string]int) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team_user WHERE id = %d`, sqlstruct.Columns(TeamUser{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM team_user WHERE team_id = %d AND user_id = %d`, sqlstruct.Columns(TeamUser{}), inputmap["team_id"], inputmap["user_id"])
	}
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "TeamUser GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "TeamUser GetOne query")
	}
}
func TeamUserGet(inputmap map[string]string) []TeamUser {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team_user WHERE id = %s`, sqlstruct.Columns(TeamUser{}), id)
	}  else if where, ok := inputmap["where"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM team_user WHERE %s`, sqlstruct.Columns(TeamUser{}), where)
	} else {
		sql = inputmap["sql"]
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "TeamUser GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []TeamUser{}
	for rows.Next() {
		localp := TeamUser{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "TeamUser Get query")
		o = append(o, localp)
	}
	return o
}
func (p *TeamUser) New(team_id, user_id int, update bool) {
	p.TeamId, p.UserId= team_id, user_id
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New TeamUser dbc.Begin")
	sql := `INSERT INTO team_user(team_id, user_id) VALUES(?, ?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New TeamUser")
	defer stmt.Close()
	log.Printf("[DEBUG] sql - %s - param '%d', '%d'\n", sql, team_id, user_id)
	res, err := stmt.Exec(team_id, user_id); u.CheckErr(err, "New teamname stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = int(_ID)
	tx.Commit()
	if update {
		p.Update()
	}
}
func (p *TeamUser) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "TeamUser dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(TeamUser{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE team_user SET %s = ? WHERE id = ?`, colname)
		stmt, err := tx.Prepare(sql)
		u.CheckErr(err, "tx.Prepare")
		defer stmt.Close()
		switch colname {
		case "id", "team_id", "user_id":
			continue
		case "ts":
			_, err := stmt.Exec("", p.ID) //Just update so trigger will fired to update ts
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "max_role":
			_, err := stmt.Exec(p.Max_role, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "access_expires":
			_, err := stmt.Exec(p.Access_expires, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "source":
			_, err := stmt.Exec(p.Source, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "expiration":
			_, err := stmt.Exec(p.Expiration, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "access_granted":
			_, err := stmt.Exec(p.Access_granted, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		default:
			fmt.Printf("UPDATE table Column '%s' not yet process\n", colname)
		}
	}
	u.CheckErr(tx.Commit(), "tx.Commit")
}
func (p *TeamUser) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM team_user WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM team_user WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM team_user WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "TeamUser dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "TeamUser Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "TeamUser Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
