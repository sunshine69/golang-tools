package model

import (
	"database/sql"
	"log"
	_ "github.com/mattn/go-sqlite3"
)

var (
	GitLabToken, SearchStr, ConfigFile, Logdbpath string
    AppConfig map[string]interface{} = map[string]interface{}{}
)

func SetUpLogDatabase() {
	conn := GetDBConn()
	defer conn.Close()
	sql := `
    CREATE TABLE IF NOT EXISTS project (
        "id"    INTEGER,
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "pid"   int DEFAULT 0,
        "weburl"    text DEFAULT "",
        "owner_id"  int DEFAULT 0,
        "owner_name"    text DEFAULT "",
        "name"  text DEFAULT "",
        "name_with_space"   text DEFAULT "",
        "path"  text DEFAULT "",
        "path_with_namespace"   text UNIQUE,
        "namespace_kind"    text DEFAULT "",
        "namespace_name"    text DEFAULT "",
        "namespace_id"  int DEFAULT 0,
        "tag_list"  text DEFAULT "",
        "labels"  text DEFAULT "",
        "gitlab_created_at" TEXT DEFAULT "",
        "is_active" INTEGER DEFAULT 1,
        "domain_ownership_confirmed"    INTEGER DEFAULT 0,
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE INDEX IF NOT EXISTS pid_idx ON project(pid);

    CREATE TRIGGER IF NOT EXISTS project_update_ts_Trigger
    AFTER UPDATE On project
    BEGIN
        UPDATE project SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;

    CREATE TABLE IF NOT EXISTS "gitlab_namespace" (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"	INTEGER,
        "name"	TEXT DEFAULT "",
        "parent_id"	INTEGER DEFAULT 0,
        "path"	TEXT DEFAULT "",
        "kind"	TEXT DEFAULT "",
        "full_path"	TEXT UNIQUE,
        "members_count_with_descendants" INTEGER DEFAULT 0,
        "gitlab_ns_id"	INTEGER DEFAULT 0,
        "domain_ownership_confirmed"	INTEGER DEFAULT 0,
        "web_url"	TEXT DEFAULT "",
        "avatar_url"	TEXT DEFAULT "",
        "billable_members_count"	INTEGER DEFAULT 0,
        "seats_in_use"	INTEGER DEFAULT 0,
        "max_seats_used"	INTEGER DEFAULT 0,
        "plan"	TEXT DEFAULT "",
        "trial_ends_on"	TEXT DEFAULT "",
        "trial"	INTEGER DEFAULT 0,
        "labels"  text DEFAULT "",
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE TRIGGER IF NOT EXISTS gitlab_namespace_update_ts_Trigger
    AFTER UPDATE On gitlab_namespace
    BEGIN
        UPDATE gitlab_namespace SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;

    CREATE TABLE IF NOT EXISTS team (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"    INTEGER,
        "name"  text DEFAULT "",
        "keyword"   TEXT DEFAULT "",
        "note"  TEXT DEFAULT "",
        "gitlab_ns_id"  INTEGER DEFAULT 0,
        "created_at"  TEXT DEFAULT "",
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE TRIGGER IF NOT EXISTS team_update_ts_Trigger
    AFTER UPDATE On team
    BEGIN
        UPDATE team SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;

    CREATE TABLE IF NOT EXISTS domain (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"    INTEGER,
        "name"  text DEFAULT "",
        "keyword"   TEXT DEFAULT "",
        "note"  TEXT DEFAULT "",
        "gitlab_ns_id"  INTEGER DEFAULT 0,
        "created_at"  TEXT DEFAULT "",
        "has_team" INTEGER DEFAULT 0,
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE TRIGGER IF NOT EXISTS domain_update_ts_Trigger
    AFTER UPDATE On domain
    BEGIN
        UPDATE domain SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;

    CREATE TABLE IF NOT EXISTS "team_project" (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"	INTEGER,
        "team_id"	int,
        "project_id"	int,
        "domain"	text DEFAULT "",
        "permission" TEXT DEFAULT "GuestPermissions",
        PRIMARY KEY("id" AUTOINCREMENT),
        CONSTRAINT "teamid-pid" UNIQUE("team_id","project_id")
    );
    CREATE TRIGGER IF NOT EXISTS team_project_update_ts_Trigger
    AFTER UPDATE On team_project
    BEGIN
        UPDATE team_project SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;
    CREATE TABLE IF NOT EXISTS "team_domain" (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"	INTEGER,
        "team_id"	int,
        "domain_id"	int,
        "permission"	TEXT DEFAULT "",
        PRIMARY KEY("id" AUTOINCREMENT),
        CONSTRAINT "teamid-did" UNIQUE("team_id","domain_id")
    );
    CREATE TRIGGER IF NOT EXISTS team_domain_update_ts_Trigger
    AFTER UPDATE On team_domain
    BEGIN
        UPDATE team_domain SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;
    CREATE TABLE IF NOT EXISTS "project_domain" (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"	INTEGER,
        "project_id"	int,
        "domain_id"	int,
        PRIMARY KEY("id" AUTOINCREMENT),
        CONSTRAINT "projectid-did" UNIQUE("project_id","domain_id")
    );
    CREATE TRIGGER IF NOT EXISTS project_domain_update_ts_Trigger
    AFTER UPDATE On project_domain
    BEGIN
        UPDATE project_domain SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;
    -- group_id - this group is identified by group_id and this group has these member of member_group_id
    CREATE TABLE IF NOT EXISTS "groupmember" (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"	INTEGER,
        "group_id"	INTEGER,
        "member_group_id"	INTEGER,
        PRIMARY KEY("id" AUTOINCREMENT)
    );
    CREATE TRIGGER IF NOT EXISTS groupmember_update_ts_Trigger
    AFTER UPDATE On groupmember
    BEGIN
        UPDATE groupmember SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;


    CREATE TABLE IF NOT EXISTS "gitlab_user" (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"	INTEGER,
        "gitlab_ns_id"	INTEGER DEFAULT -1,
        "gitlab_user_id" INTEGER DEFAULT 0,
        "username" TEXT DEFAULT "",
        "email" TEXT,
        "name" TEXT DEFAULT "",
        "state" INTEGER DEFAULT -1,
        "web_url" TEXT DEFAULT "",
        "created_at" TEXT DEFAULT "",
        "bio" TEXT DEFAULT "",
        "location" TEXT DEFAULT "",
        "public_email" TEXT DEFAULT "",
        "skype" TEXT DEFAULT "",
        "linkedin" TEXT DEFAULT "",
        "twitter" TEXT DEFAULT "",
        "website_url" TEXT DEFAULT "",
        "organization" TEXT DEFAULT "",
        "extern_uid" TEXT DEFAULT "",
        "provider" TEXT DEFAULT "",
        "theme_id" INTEGER DEFAULT -1,
        "last_activity_on" TEXT DEFAULT "",
        "color_scheme_id" INTEGER DEFAULT -1,
        "is_admin" INTEGER DEFAULT 0,
        "avatar_url" TEXT DEFAULT "",
        "can_create_group" INTEGER DEFAULT 0,
        "can_create_project" INTEGER DEFAULT 0,
        "projects_limit" INTEGER DEFAULT 0,
        "current_sign_in_at" TEXT DEFAULT "",
        "last_sign_in_at" TEXT DEFAULT "",
        "confirmed_at" TEXT DEFAULT "",
        "two_factor_enabled" INTEGER DEFAULT 0,
        "note" TEXT DEFAULT "",
        "identities" TEXT DEFAULT "",
        "external" INTEGER DEFAULT 0,
        "private_profile" INTEGER DEFAULT 0,
        "shared_runners_minutes_limit" INTEGER DEFAULT 0,
        "extra_shared_runners_minutes_limit" INTEGER DEFAULT 0,
        "using_license_seat" INTEGER DEFAULT 0,
        "custom_attributes" TEXT DEFAULT "",
        PRIMARY KEY("id" AUTOINCREMENT),
        CONSTRAINT "gilab-id" UNIQUE("gitlab_user_id"),
        CONSTRAINT "gilab-email" UNIQUE("email"),
        CONSTRAINT "gilab-username" UNIQUE("username")
    );

    CREATE TRIGGER IF NOT EXISTS gitlab_user_update_ts_Trigger
    AFTER UPDATE On gitlab_user
    BEGIN
        UPDATE gitlab_user SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;

    CREATE TABLE IF NOT EXISTS "team_user" (
        ts TEXT DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
        "id"	INTEGER,
        "team_id"	int,
        "user_id"	int,
        "max_role"	    text DEFAULT "",
        "access_expires" text DEFAULT "",
        "source" text DEFAULT "",
        "expiration" text DEFAULT "",
        "access_granted" text DEFAULT "",
        PRIMARY KEY("id" AUTOINCREMENT),
        CONSTRAINT "teamid-pid" UNIQUE("team_id","user_id")
    );
    CREATE TRIGGER IF NOT EXISTS team_user_update_ts_Trigger
    AFTER UPDATE On team_user
    BEGIN
        UPDATE team_user SET ts = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = NEW.id;
    END;

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
