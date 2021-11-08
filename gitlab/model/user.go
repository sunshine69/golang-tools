package model

import (
	"fmt"
	"log"
	"strings"

	"github.com/sunshine69/sqlstruct"
	u "github.com/sunshine69/golang-tools/utils"
)

type User struct {
	ID                int   `sql:"id"`
	TS         string   `sql:"ts"`
	GitlabNsID int `sql:"gitlab_ns_id"`
	GitlabUserId int `sql:"gitlab_user_id"`
	GitlabUserName string `sql:"username"`
	Email string `sql:"email"`
	Name string `sql:"name"`
	State int `sql:"state"`
	WebUrl string `sql:"web_url"`
	CreatedAt string `sql:"created_at"`
	Bio string `sql:"bio"`
	Location string `sql:"location"`
	PublicEmail string `sql:"public_email"`
	Skype string `sql:"skype"`
	Linkedin string `sql:"linkedin"`
	Twitter string `sql:"twitter"`
	Website_url string `sql:"website_url"`
	Organization string `sql:"organization"`
	Extern_uid string `sql:"extern_uid"`
	Provider string `sql:"provider"`
	Theme_id int `sql:"theme_id"`
	Last_activity_on string `sql:"last_activity_on"`
	Color_scheme_id int `Sql:"Color_scheme_id"`
	Is_admin int `sql:"is_admin"`
	Avatar_url string `sql:"avatar_url"`
	Can_create_group int `sql:"can_create_group"`
	Can_create_project int `sql:"can_create_project"`
	Projects_limit int `sql:"projects_limit"`
	Current_sign_in_at string `sql:"current_sign_in_at"`
	Last_sign_in_at string `sql:"last_sign_in_at"`
	Confirmed_at string `sql:"confirmed_at"`
	Two_factor_enabled int `sql:"two_factor_enabled"`
	Note string `sql:"note"`
	Identities string `sql:"identities"`
	External int `sql:"external"`
	Private_profile int `sql:"private_profile"`
	Shared_runners_minutes_limit int `sql:"shared_runners_minutes_limit"`
	Extra_shared_runners_minutes_limit int `sql:"extra_shared_runners_minutes_limit"`
	Using_license_seat int `sql:"using_license_seat"`
	Custom_attributes string `sql:"custom_attributes"`
}
func UserNew(email string) User {
	p := User{}
	p.GetOne(map[string]string{"where": fmt.Sprintf("email = '%s'", email)})
	if p.ID == 0 {
		p.New(email, false)
		//Update struct with database default value
		p.GetOne(map[string]string{"id": fmt.Sprintf("%d", p.ID)})
	}
	return p
}
func (p *User) GetOne(inputmap map[string]string) {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM gitlab_user WHERE id = %s`, sqlstruct.Columns(User{}), id)
	} else {
		sql = fmt.Sprintf(`SELECT %s FROM gitlab_user WHERE %s`, sqlstruct.Columns(User{}), inputmap["where"])
	}
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "User GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	if rows.Next() {
		err = sqlstruct.Scan(p, rows)
		u.CheckErr(err, "User GetOne query")
	}
}
func UserGet(inputmap map[string]string) []User {
	dbc := GetDBConn()
	defer dbc.Close()
	sql := ""
	if id, ok := inputmap["id"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM gitlab_user WHERE id = %s`, sqlstruct.Columns(User{}), id)
	} else if where, ok := inputmap["where"]; ok {
		sql = fmt.Sprintf(`SELECT %s FROM gitlab_user WHERE %s`, sqlstruct.Columns(User{}), where)
	} else {
		sql = inputmap["sql"]
	}
	sql = sql + ` ORDER BY id DESC`
	stmt, err := dbc.Prepare(sql)
	u.CheckErr(err, "User GetOne")
	defer stmt.Close()
	rows, _ := stmt.Query()
	defer rows.Close()
	o := []User{}
	for rows.Next() {
		localp := User{}
		err = sqlstruct.Scan(&localp, rows)
		u.CheckErr(err, "User Get query")
		o = append(o, localp)
	}
	return o
}
func (p *User) New(email string, update bool) {
	p.Email = email
	dbc := GetDBConn();	defer dbc.Close()
	tx, err := dbc.Begin(); u.CheckErrNonFatal(err, "New user by email dbc.Begin")
	sql := `INSERT INTO gitlab_user(email) VALUES(?)`
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "New user by email")
	defer stmt.Close()
	log.Printf("[DEBUG] sql - %s - param '%s'\n", sql, email)
	res, err := stmt.Exec(email); u.CheckErr(err, "New user by email stmt.Exec")
	_ID, _ := res.LastInsertId()
	p.ID = int(_ID)
	tx.Commit()
	if update {
		p.Update()
	}
}
func (p *User) Update() {
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "dbc.Begin")
	for _, colname := range strings.Split(sqlstruct.Columns(User{}), ",") {
		colname = strings.TrimSpace(colname)
		sql := fmt.Sprintf(`UPDATE gitlab_user SET %s = ? WHERE id = ?`, colname)
		stmt, err := tx.Prepare(sql)
		u.CheckErr(err, "tx.Prepare")
		defer stmt.Close()
		switch colname {
		case "id", "ts":
			continue
		case "gitlab_ns_id":
			_, err := stmt.Exec(p.GitlabNsID, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "gitlab_user_id":
			_, err = stmt.Exec(p.GitlabUserId, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "username":
			_, err = stmt.Exec(p.GitlabUserName, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "email":
			_, err = stmt.Exec(p.Email, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "name":
			_, err = stmt.Exec(p.Name, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "state":
			_, err = stmt.Exec(p.State, p.ID)
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
		case "created_at":
			_, err = stmt.Exec(p.CreatedAt, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "bio":
			_, err = stmt.Exec(p.Bio, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "location":
			_, err = stmt.Exec(p.Location, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "public_email":
			_, err = stmt.Exec(p.PublicEmail, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "skype":
			_, err = stmt.Exec(p.Skype, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "linkedin":
			_, err = stmt.Exec(p.Linkedin, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "twitter":
			_, err = stmt.Exec(p.Twitter, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "website_url":
			_, err = stmt.Exec(p.Website_url, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "organization":
			_, err = stmt.Exec(p.Organization, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "extern_uid":
			_, err = stmt.Exec(p.Extern_uid, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "provider":
			_, err = stmt.Exec(p.Provider, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "theme_id":
			_, err = stmt.Exec(p.Theme_id, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "last_activity_on":
			_, err = stmt.Exec(p.Last_activity_on, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "color_scheme_id":
			_, err = stmt.Exec(p.Color_scheme_id, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "is_admin":
			_, err = stmt.Exec(p.Is_admin, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "avatar_url":
			_, err = stmt.Exec(p.Avatar_url, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "can_create_group":
			_, err = stmt.Exec(p.Can_create_group, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "can_create_project":
			_, err = stmt.Exec(p.Can_create_project, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "projects_limit":
			_, err = stmt.Exec(p.Projects_limit, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "current_sign_in_at":
			_, err = stmt.Exec(p.Current_sign_in_at, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "last_sign_in_at":
			_, err = stmt.Exec(p.Last_sign_in_at, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "confirmed_at":
			_, err = stmt.Exec(p.Confirmed_at, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "two_factor_enabled":
			_, err = stmt.Exec(p.Two_factor_enabled, p.ID)
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
		case "identities":
			_, err = stmt.Exec(p.Identities, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "external":
			_, err = stmt.Exec(p.External, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "private_profile":
			_, err = stmt.Exec(p.Private_profile, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "shared_runners_minutes_limit":
			_, err = stmt.Exec(p.Shared_runners_minutes_limit, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "extra_shared_runners_minutes_limit":
			_, err = stmt.Exec(p.Extra_shared_runners_minutes_limit, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "using_license_seat":
			_, err = stmt.Exec(p.Using_license_seat, p.ID)
			if u.CheckErrNonFatal(err, "Exec") != nil {
				tx.Rollback()
				log.Fatal("aborted due to error\n")
			}
		case "custom_attributes":
			_, err = stmt.Exec(p.Custom_attributes, p.ID)
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
func (p *User) Delete(inputmap map[string]string) {
	sql := ""
	if inputmap == nil {
		sql = fmt.Sprintf(`DELETE FROM gitlab_user WHERE id = %d`, p.ID)
	} else {
		if id, ok := inputmap["id"]; ok {
			sql = fmt.Sprintf(`DELETE FROM gitlab_user WHERE id = %s`, id)
		} else {
			sql = fmt.Sprintf(`DELETE FROM gitlab_user WHERE %s`, inputmap["where"])
		}
	}
	dbc := GetDBConn()
	defer dbc.Close()
	tx, err := dbc.Begin()
	u.CheckErr(err, "User dbc.Begin")
	stmt, err := tx.Prepare(sql); u.CheckErr(err, "User Delete")
	defer stmt.Close()
	_, err = stmt.Exec()
	if u.CheckErrNonFatal(err, "User Delete") != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
