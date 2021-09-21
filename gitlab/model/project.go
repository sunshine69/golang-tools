package model

import (
	"github.com/sunshine69/sqlstruct"
    "fmt"
    "log"
    u "localhost.com/utils"
    "strings"
)

type Project struct {
    ID  uint `sql:"id"`
    Pid uint `sql:"pid"`
    Weburl  string `sql:"weburl"`
    OwnerId int `sql:"owner_id"`
    OwnerName   string `sql:"owner_name"`
    Name    string `sql:"name"`
    NameWithSpace   string `sql:"name_with_space"`
    Path    string `sql:"path"`
    PathWithNamespace   string `sql:"path_with_namespace"`
    NamespaceKind   string `sql:"namespace_kind"`
    NamespaceName   string `sql:"namespace_name"`
    NamespaceId int `sql:"namespace_id"`
    TagList string `sql:"tag_list"`
    GitlabCreatedAt string `sql:"gitlab_created_at"`
    IsActive    uint8 `sql:"is_active"`
    DomainOwnershipConfirmed    uint8 `sql:"domain_ownership_confirmed"`
}
func (p *Project) GetOne(inputmap map[string]string) {
    dbc := GetDBConn(); defer dbc.Close()
    sql := ""
    if id, ok := inputmap["id"]; ok {
        sql = fmt.Sprintf(`SELECT %s FROM project WHERE id = %s`, sqlstruct.Columns(Project{}) ,id)
    } else {
        sql = fmt.Sprintf(`SELECT %s FROM project WHERE %s`, sqlstruct.Columns(Project{}), inputmap["where"])
    }
    sql = sql + ` ORDER BY id DESC`
    log.Printf("[DEBUG] sql %s\n", sql)
    stmt, err := dbc.Prepare(sql)
    u.CheckErr(err, "Project GetOne");  defer stmt.Close()
    rows, _ := stmt.Query(); defer rows.Close()
    if rows.Next(){
        err = sqlstruct.Scan(p, rows)
        u.CheckErr(err, "Project GetOne query")
    }
}
func (p *Project) Get(inputmap map[string]string) []Project {
    dbc := GetDBConn(); defer dbc.Close()
    sql := ""
    if id, ok := inputmap["id"]; ok {
        sql = fmt.Sprintf(`SELECT %s FROM project WHERE id = %s`, sqlstruct.Columns(Project{}), id)
    } else {
        sql = fmt.Sprintf(`SELECT %s FROM project WHERE %s`, sqlstruct.Columns(Project{}), inputmap["where"])
    }
    sql = sql + ` ORDER BY id DESC`
    stmt, err := dbc.Prepare(sql)
    u.CheckErr(err, "GetOne");  defer stmt.Close()
    rows, _ := stmt.Query(); defer rows.Close()
    o := []Project{}
    for rows.Next() {
        localp := Project{}
        err = sqlstruct.Scan(&localp, rows)
        u.CheckErr(err, "Get query")
        o = append(o, localp)
    }
    return o
}
func (p *Project) New(path_with_namespace string, update bool) {
    p.PathWithNamespace = path_with_namespace
    dbc := GetDBConn(); defer dbc.Close()
    tx, err := dbc.Begin(); u.CheckErr(err, "Project new")
    stmt, _ := tx.Prepare( `INSERT INTO project(path_with_namespace) VALUES(?)` ); defer stmt.Close()
    res, err := stmt.Exec(path_with_namespace)
    u.CheckErr(err, "New stmt.Exec")
    _ID, _ := res.LastInsertId()
    p.ID = uint(_ID)
    tx.Commit()
    if update {
        p.Update()
    }
}
func (p *Project) Update() {
    dbc := GetDBConn(); defer dbc.Close()
    tx, err := dbc.Begin()
    u.CheckErr(err, "dbc.Begin")
    for _, colname := range strings.Split(sqlstruct.Columns(Project{}), ",") {
        colname = strings.TrimSpace(colname)
        sql := fmt.Sprintf(`UPDATE project SET %s = ? WHERE id = ?`, colname)
        stmt, err := tx.Prepare(sql)
        u.CheckErr(err, "tx.Prepare"); defer stmt.Close()
        switch colname {
        case "id":
            continue
        case "pid":
            _, err = stmt.Exec(p.Pid, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "weburl":
            _, err = stmt.Exec(p.Weburl, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "owner_id":
            _, err = stmt.Exec(p.OwnerId, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "owner_name":
            _, err := stmt.Exec(p.OwnerName, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "name":
            _, err := stmt.Exec(p.Name, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "name_with_space":
            _, err = stmt.Exec(p.NameWithSpace, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "path":
            _, err = stmt.Exec(p.Path, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "path_with_namespace":
            _, err = stmt.Exec(p.PathWithNamespace, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "namespace_kind":
            _, err = stmt.Exec(p.NamespaceKind, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "namespace_name":
            _, err = stmt.Exec(p.NamespaceName, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "namespace_id":
            _, err = stmt.Exec(p.NamespaceId, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "tag_list":
            _, err = stmt.Exec(p.TagList, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "gitlab_created_at":
            _, err = stmt.Exec(p.GitlabCreatedAt, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "is_active":
            _, err = stmt.Exec(p.IsActive, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        case "domain_ownership_confirmed":
            _, err = stmt.Exec(p.DomainOwnershipConfirmed, p.ID)
            if u.CheckErrNonFatal(err, "Exec") != nil {
                tx.Rollback()
                log.Fatalf("aborted due to error")
            }
        default:
            log.Printf("[DEBUG] Not matching anything with this %s\n", colname)
        }
    }
    u.CheckErr( tx.Commit(), "tx.Commit" )
}
func (p *Project) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM project WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM project WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM project WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "Project dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "Project Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "Project Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
