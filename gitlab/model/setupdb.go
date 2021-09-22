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
        "weburl"    text DEFAULT "",
        "owner_id"  int,
        "owner_name"    text DEFAULT "",
        "name"  text DEFAULT "",
        "name_with_space"   text DEFAULT "",
        "path"  text DEFAULT "",
        "path_with_namespace"   text UNIQUE,
        "namespace_kind"    text DEFAULT "",
        "namespace_name"    text DEFAULT "",
        "namespace_id"  int,
        "tag_list"  text DEFAULT "",
        "labels"  text DEFAULT "",
        "gitlab_created_at" DATETIME,
        "is_active" INTEGER DEFAULT 1,
        "domain_ownership_confirmed"    INTEGER DEFAULT 0,
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE INDEX IF NOT EXISTS pid_idx ON project(pid);

    CREATE TABLE IF NOT EXISTS "gitlab_namespace" (
        "id"	INTEGER,
        "name"	TEXT DEFAULT "",
        "parent_id"	INTEGER,
        "path"	TEXT DEFAULT "",
        "kind"	TEXT DEFAULT "",
        "full_path"	TEXT UNIQUE,
        "members_count_with_descendants"	INTEGER,
        "gitlab_ns_id"	INTEGER,
        "domain_ownership_confirmed"	INTEGER DEFAULT 0,
        "web_url"	TEXT DEFAULT "",
        "avatar_url"	TEXT DEFAULT "",
        "billable_members_count"	INTEGER,
        "seats_in_use"	INTEGER,
        "max_seats_used"	INTEGER,
        "plan"	TEXT DEFAULT "",
        "trial_ends_on"	TEXT DEFAULT "",
        "trial"	INTEGER DEFAULT 0,
        "labels"  text DEFAULT "",
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE TABLE IF NOT EXISTS team (
        "id"    INTEGER,
        "name"  text DEFAULT "",
        "keyword"   TEXT DEFAULT "",
        "note"  TEXT DEFAULT "",
        "gitlab_ns_id"  INTEGER DEFAULT -1,
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE TABLE IF NOT EXISTS domain (
        "id"    INTEGER,
        "name"  text DEFAULT "",
        "keyword"   TEXT DEFAULT "",
        "note"  TEXT DEFAULT "",
        "gitlab_ns_id"  INTEGER DEFAULT -1,
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE TABLE IF NOT EXISTS "team_project" (
        "id"	INTEGER,
        "team_id"	int,
        "project_id"	int,
        "domain"	text DEFAULT "",
        PRIMARY KEY("id" AUTOINCREMENT),
        CONSTRAINT "teamid-pid" UNIQUE("team_id","project_id")
    );
    CREATE TABLE IF NOT EXISTS "team_domain" (
        "id"	INTEGER,
        "team_id"	int,
        "domain_id"	int,
        PRIMARY KEY("id" AUTOINCREMENT),
        CONSTRAINT "teamid-did" UNIQUE("team_id","domain_id")
    );
    CREATE TABLE IF NOT EXISTS "project_domain" (
        "id"	INTEGER,
        "project_id"	int,
        "domain_id"	int,
        PRIMARY KEY("id" AUTOINCREMENT),
        CONSTRAINT "projectid-did" UNIQUE("project_id","domain_id")
    );
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
