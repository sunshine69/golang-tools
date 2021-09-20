package main

import (
	"log"
	"github.com/sunshine69/sqlstruct"
    "fmt"
    u "localhost.com/utils"
    "strings"
)

type GitlabNamespace struct {
    ID  uint `sql:"id"`
    Name    string `sql:"name"`
    ParentId uint `sql:"parent_id"`
    Path    string `sql:"path"`
    Kind string `sql:"kind"`
    FullPath   string `sql:"full_path"`
    MembersCountWithDescendants uint `sql:"members_count_with_descendants"`
    GitlabNamespaceId uint `sql:"gitlab_ns_id"`
    DomainOwnershipConfirmed    uint8 `sql:"domain_ownership_confirmed"`
    WebUrl string `sql:"web_url"`
    AvatarUrl string `sql:"avatar_url"`
    BillableMembersCount uint `sql:"billable_members_count"`
    Seats_in_use uint `sql:"seats_in_use"`
    Max_seats_used uint `sql:"max_seats_used"`
    Plan string `sql:"plan"`
    Trial_ends_on string `sql:"trial_ends_on"`
    Trial uint `sql:"trial"`
}

func (p *GitlabNamespace) GetOne(inputmap map[string]string) {
    dbc := GetDBConn(); defer dbc.Close()
    sql := ""
    if id, ok := inputmap["id"]; ok {
        sql = fmt.Sprintf(`SELECT %s FROM gitlab_namespace WHERE id = %s`, sqlstruct.Columns(GitlabNamespace{}) ,id)
    } else {
        sql = fmt.Sprintf(`SELECT %s FROM gitlab_namespace WHERE %s`, sqlstruct.Columns(GitlabNamespace{}), inputmap["where"])
    }
    sql = sql + ` ORDER BY id DESC`
    log.Printf("[DEBUG] sql %s\n", sql)
    stmt, err := dbc.Prepare(sql)
    u.CheckErr(err, "GitlabNamespace GetOne");  defer stmt.Close()
    rows, _ := stmt.Query(); defer rows.Close()
    if rows.Next(){
        err = sqlstruct.Scan(p, rows)
        u.CheckErr(err, "Gitlabnamespace GetOne query")
    }
}
func (p *GitlabNamespace) Get(inputmap map[string]string) []GitlabNamespace {
    dbc := GetDBConn(); defer dbc.Close()
    sql := ""
    if id, ok := inputmap["id"]; ok {
        sql = fmt.Sprintf(`SELECT %s FROM gitlab_namespace WHERE id = %s`, sqlstruct.Columns(GitlabNamespace{}), id)
    } else {
        sql = fmt.Sprintf(`SELECT %s FROM gitlab_namespace WHERE %s`, sqlstruct.Columns(GitlabNamespace{}), inputmap["where"])
    }
    sql = sql + ` ORDER BY id DESC`
    stmt, err := dbc.Prepare(sql)
    u.CheckErr(err, "GitlabNamespace GetOne");  defer stmt.Close()
    rows, _ := stmt.Query(); defer rows.Close()
    o := []GitlabNamespace{}
    for rows.Next() {
        localp := GitlabNamespace{}
        err = sqlstruct.Scan(&localp, rows)
        u.CheckErr(err, "GitlabNamespace Get query")
        o = append(o, localp)
    }
    return o
}
func (p *GitlabNamespace) New(full_path string, update bool) {
    dbc := GetDBConn(); defer dbc.Close()
    stmt, _ := dbc.Prepare( `INSERT INTO gitlab_namespace(full_path) VALUES(?)` ); defer stmt.Close()
    res, err := stmt.Exec(full_path)
    u.CheckErr(err, "New GitlabNamespace stmt.Exec")
    _ID, _ := res.LastInsertId()
    p.ID = uint(_ID)
    if update {
        p.Update()
    }
}
func (p *GitlabNamespace) Update() {
    dbc := GetDBConn(); defer dbc.Close()
    tx, err := dbc.Begin()
    u.CheckErr(err, "dbc.Begin")
    for _, colname := range strings.Split(sqlstruct.Columns(GitlabNamespace{}), ",") {
        colname = strings.TrimSpace(colname)
        sql := fmt.Sprintf(`UPDATE gitlab_namespace SET %s = ? WHERE id = ?`, colname)
        stmt, err := tx.Prepare(sql)
        u.CheckErr(err, "tx.Prepare"); defer stmt.Close()
        switch colname {
        case "id", "full_path":
            continue
        case "name":
            _, err := stmt.Exec(p.Name, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "parent_id":
            _, err = stmt.Exec(p.ParentId, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "path":
            _, err = stmt.Exec(p.Path, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "kind":
            _, err = stmt.Exec(p.Kind, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "members_count_with_descendants":
            _, err = stmt.Exec(p.MembersCountWithDescendants, p.ID)
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
        case "domain_ownership_confirmed":
            _, err = stmt.Exec(p.DomainOwnershipConfirmed, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "web_url":
            _, err = stmt.Exec(p.WebUrl, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "avatar_url":
            _, err = stmt.Exec(p.AvatarUrl, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "billable_members_count":
            _, err = stmt.Exec(p.BillableMembersCount, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "seats_in_use":
            _, err = stmt.Exec(p.Seats_in_use, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "max_seats_used":
            _, err = stmt.Exec(p.Max_seats_used, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "plan":
            _, err = stmt.Exec(p.Plan, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "trial_ends_on":
            _, err = stmt.Exec(p.Trial_ends_on, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatal("aborted due to error\n")
            }
        case "trial":
            _, err = stmt.Exec(p.Trial, p.ID)
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
