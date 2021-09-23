package model

import (
	"fmt"
	"log"
	"strings"

	"github.com/sunshine69/sqlstruct"
	u "localhost.com/utils"
)
type Groupmember struct {
	ID         int   `sql:"id"`
	GroupId    int   `sql:"group_id"`
	MemberGroupId    int   `sql:"member_group_id"`
	TS         string   `sql:"ts"`
}
func GroupmemberNew(group_id, member_group_id int) Groupmember {
	p := Groupmember{}
	p.GetOne(map[string]string{"where": fmt.Sprintf("group_id = %d AND member_group_id = %d", group_id, member_group_id)})
	if p.ID == 0 {
		p.New(group_id, member_group_id, false)
		p.GetOne(map[string]string{"id": fmt.Sprintf("%d", p.ID)})
	}
	return p
}
func (p *Groupmember) GetOne(inputmap map[string]string) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM groupmember WHERE id = %s`, sqlstruct.Columns(Groupmember{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM groupmember WHERE %s`, sqlstruct.Columns(Groupmember{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "Groupmember GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "Groupmember GetOne query")
	}
}
func GroupmemberGet(inputmap map[string]string) []Groupmember {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM groupmember WHERE id = %s`, sqlstruct.Columns(Groupmember{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM groupmember WHERE %s`, sqlstruct.Columns(Groupmember{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "Groupmember GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []Groupmember{}
	for rows.Next() {
		localp := Groupmember{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "Groupmember Get query")
		o = append(o, localp)
	}
	return o
}
func (p *Groupmember) New(group_id, member_group_id int, update bool) {
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New groupmembername dbc.Begin")
	sql := `INSERT INTO groupmember(group_id, member_group_id) VALUES(?, ?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New groupmember")
	defer stmt.Close()
	log.Printf("[DEBUG] sql - %d - param '%d'\n", group_id, member_group_id)
	res, err := stmt.Exec(group_id, member_group_id); u.CheckErr(err, "New groupmember stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = int(_ID)
	tx.Commit()
	if update {
		p.Update()
	}
}
func (p *Groupmember) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(Groupmember{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE groupmember SET %s = ? WHERE id = ?`, colname)
		stmt, err := tx.Prepare(sql)
		u.CheckErr(err, "tx.Prepare")
		defer stmt.Close()
		switch colname {
		case "id", "group_id", "member_group_id":
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
func (p *Groupmember) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM groupmember WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM groupmember WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM groupmember WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "Groupmember dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "Groupmember Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "Groupmember Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
