package model

import (
	"fmt"
	"log"
	"strings"

	"github.com/sunshine69/sqlstruct"
	u "localhost.com/utils"
)

type Domain struct {
	ID                uint   `sql:"id"`
	Name              string `sql:"name"`
	Keyword           string `sql:"keyword"`
	Note              string `sql:"note"`
	GitlabNamespaceId int    `sql:"gitlab_ns_id"`
}
func (p *Domain) GetOrNew(name string) {
	p.GetOne(map[string]string{"where": fmt.Sprintf("name = '%s'", name)})
	if p.ID == 0 {
		p.New(name, false)
	}
}
func (p *Domain) GetOne(inputmap map[string]string) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM domain WHERE id = %s`, sqlstruct.Columns(Domain{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM domain WHERE %s`, sqlstruct.Columns(Domain{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "Domain GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "Domain GetOne query")
	}
}
func (p *Domain) Get(inputmap map[string]string) []Domain {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM domain WHERE id = %s`, sqlstruct.Columns(Domain{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM domain WHERE %s`, sqlstruct.Columns(Domain{}), inputmap["where"])
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "Domain GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []Domain{}
	for rows.Next() {
		localp := Domain{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "Domain Get query")
		o = append(o, localp)
	}
	return o
}
func (p *Domain) New(domainname string, update bool) {
	p.Name = domainname
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New domainname dbc.Begin")
	sql := `INSERT INTO domain(name) VALUES(?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New domainname")
	defer stmt.Close()
	log.Printf("[DEBUG] sql - %s - param '%s'\n", sql, domainname)
	res, err := stmt.Exec(domainname); u.CheckErr(err, "New domainname stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = uint(_ID)
	tx.Commit()
	if update {
		p.Update()
	}
}
func (p *Domain) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(Domain{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE domain SET %s = ? WHERE id = ?`, colname)
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
func (p *Domain) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM domain WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM domain WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM domain WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "Domain dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "Domain Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "Domain Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
