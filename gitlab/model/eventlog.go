package model

import (
	"fmt"
	"log"
	"strings"

	"github.com/sunshine69/sqlstruct"
	u "github.com/sunshine69/golang-tools/utils"
)

type EventLog struct {
	ID                int    `sql:"id"`
	Host              string `sql:"host"`
	Application       string `sql:"application"`
	Message           string `sql:"message"`
	Logfile           string `sql:"logfile"`
	TS                string `sql:"ts"`
}
func EventLogNew(message string) EventLog {
	p := EventLog{}
	p.New(message, false)
	return p
}
func (p *EventLog) GetOne(inputmap map[string]string) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM eventlog WHERE id = %s`, sqlstruct.Columns(EventLog{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM eventlog WHERE %s`, sqlstruct.Columns(EventLog{}), inputmap["where"])
	}
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "EventLog GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "EventLog GetOne query")
	}
}
func EventLogGet(inputmap map[string]string) []EventLog {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM eventlog WHERE id = %s`, sqlstruct.Columns(EventLog{}), id)
	} else if where, ok := inputmap["where"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM eventlog WHERE %s`, sqlstruct.Columns(EventLog{}), where)
	} else {
		sql = inputmap["sql"]
	}
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "EventLogGet")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []EventLog{}
	for rows.Next() {
		localp := EventLog{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "EventLog Get query")
		o = append(o, localp)
	}
	return o
}
func (p *EventLog) New(message string, update bool) {
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New EventLogname dbc.Begin")
	sql := `INSERT INTO eventlog(message) VALUES(?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New EventLogname")
	defer stmt.Close()
	res, err := stmt.Exec(message); u.CheckErr(err, "New EventLogname stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = int(_ID)
	tx.Commit()
	p.Message = message
	if update {
		p.Update()
	}
}
func (p *EventLog) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(EventLog{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE eventlog SET %s = ? WHERE id = ?`, colname)
		stmt, err := tx.Prepare(sql)
		u.CheckErr(err, "tx.Prepare")
		defer stmt.Close()
		switch colname {
		case "id", "ts":
			continue
		case "host":
			_, err := stmt.Exec(p.Host, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "application":
			_, err = stmt.Exec(p.Application, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "message":
			_, err = stmt.Exec(p.Message, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "logfile":
			_, err = stmt.Exec(p.Logfile, p.ID)
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
func (p *EventLog) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM eventlog WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM eventlog WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM eventlog WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "EventLog dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "EventLog Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "EventLog Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
