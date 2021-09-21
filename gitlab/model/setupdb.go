package model

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var (
	GitLabToken, SearchStr, ConfigFile, Logdbpath string
)

func SetUpLogDatabase() {
	conn := GetDBConn()
	defer conn.Close()
	sql := `
    CREATE TABLE IF NOT EXISTS project (
        "id"    INTEGER,
        "pid"   int,
        "weburl"    text,
        "owner_id"  int,
        "owner_name"    text,
        "name"  text,
        "name_with_space"   text,
        "path"  text,
        "path_with_namespace"   text UNIQUE,
        "namespace_kind"    text,
        "namespace_name"    text,
        "namespace_id"  int,
        "tag_list"  text,
        "gitlab_created_at" DATETIME,
        "is_active" INTEGER DEFAULT 1,
        "domain_ownership_confirmed"    INTEGER DEFAULT 0,
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE INDEX IF NOT EXISTS pid_idx ON project(pid);

    CREATE TABLE IF NOT EXISTS "gitlab_namespace" (
        "id"	INTEGER,
        "name"	TEXT,
        "parent_id"	INTEGER,
        "path"	TEXT,
        "kind"	TEXT,
        "full_path"	TEXT UNIQUE,
        "members_count_with_descendants"	INTEGER,
        "gitlab_ns_id"	INTEGER,
        "domain_ownership_confirmed"	INTEGER DEFAULT 0,
        "web_url"	TEXT,
        "avatar_url"	TEXT,
        "billable_members_count"	INTEGER,
        "seats_in_use"	INTEGER,
        "max_seats_used"	INTEGER,
        "plan"	TEXT,
        "trial_ends_on"	TEXT,
        "trial"	INTEGER DEFAULT 0,
        PRIMARY KEY("id" AUTOINCREMENT)
    );

    CREATE TABLE IF NOT EXISTS team (
        "id"    INTEGER,
        "name"  text,
        "keyword"   TEXT,
        "note"  TEXT,
        "gitlab_ns_id"  INTEGER DEFAULT -1,
        PRIMARY KEY("id" AUTOINCREMENT)
    );

    CREATE TABLE IF NOT EXISTS team_project(id INTEGER PRIMARY KEY AUTOINCREMENT, team_id int, project_id int, domain text);

    PRAGMA main.page_size = 4096;
    PRAGMA main.cache_size=10000;
    PRAGMA main.locking_mode=EXCLUSIVE;
    PRAGMA main.synchronous=NORMAL;
    PRAGMA main.journal_mode=WAL;
    PRAGMA main.cache_size=5000;`

	log.Printf("[INFO] Set up database schema\n")
	_, err := conn.Exec(sql)
	if err != nil {
		panic(err)
	}
}

//GetDBConn -
func GetDBConn() *sql.DB {
	db, err := sql.Open("sqlite3", Logdbpath)
	if err != nil {
		panic(err)
	}
	if db == nil {
		panic("db nil")
	}
	return db
}
