package main

import (
	"log"
	"github.com/sunshine69/sqlstruct"
    "fmt"
    u "localhost.com/utils"
    "strings"
)

type Team struct {
    ID  uint `sql:"id"`
    Name    string `sql:"name"`
    Keyword string `sql:"keyword"`
    Note    string `sql:"note"`
    GitlabNamespaceId int `sql:"gitlab_ns_id"`
}

func (p *Team) GetOne(inputmap map[string]string) {
    dbc := GetDBConn(); defer dbc.Close()
    sql := ""
    if id, ok := inputmap["id"]; ok {
        sql = fmt.Sprintf(`SELECT %s FROM team WHERE id = %s`, sqlstruct.Columns(Team{}) ,id)
    } else {
        sql = fmt.Sprintf(`SELECT %s FROM team WHERE %s`, sqlstruct.Columns(Team{}), inputmap["where"])
    }
    sql = sql + ` ORDER BY id DESC`
    stmt, err := dbc.Prepare(sql)
    u.CheckErr(err, "Team GetOne");  defer stmt.Close()
    rows, _ := stmt.Query(); defer rows.Close()
    if rows.Next(){
        err = sqlstruct.Scan(p, rows)
        u.CheckErr(err, "Team GetOne query")
    }
}
func (p *Team) Get(inputmap map[string]string) []Team {
    dbc := GetDBConn(); defer dbc.Close()
    sql := ""
    if id, ok := inputmap["id"]; ok {
        sql = fmt.Sprintf(`SELECT %s FROM team WHERE id = %s`, sqlstruct.Columns(Team{}), id)
    } else {
        sql = fmt.Sprintf(`SELECT %s FROM team WHERE %s`, sqlstruct.Columns(Team{}), inputmap["where"])
    }
    sql = sql + ` ORDER BY id DESC`
    stmt, err := dbc.Prepare(sql)
    u.CheckErr(err, "Team GetOne");  defer stmt.Close()
    rows, _ := stmt.Query(); defer rows.Close()
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
    dbc := GetDBConn(); defer dbc.Close()
    stmt, _ := dbc.Prepare( `INSERT INTO team(name) VALUES(?)` ); defer stmt.Close()
    res, err := stmt.Exec(teamname)
    u.CheckErr(err, "New stmt.Exec")
    _ID, _ := res.LastInsertId()
    p.ID = uint(_ID)
    if update {
        p.Update()
    }
}
func (p *Team) Update() {
    dbc := GetDBConn(); defer dbc.Close()
    tx, err := dbc.Begin()
    u.CheckErr(err, "dbc.Begin")
    for _, colname := range strings.Split(sqlstruct.Columns(Team{}), ",") {
        colname = strings.TrimSpace(colname)
        sql := fmt.Sprintf(`UPDATE team SET %s = ? WHERE id = ?`, colname)
        stmt, err := tx.Prepare(sql)
        u.CheckErr(err, "tx.Prepare"); defer stmt.Close()
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
    u.CheckErr( tx.Commit(), "tx.Commit" )
}
