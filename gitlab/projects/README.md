# data source

- use gitlab golang sdk to pull data and update the local db to refect what we want
- also use various sources to get Project - Domain relationship

From ticket [DNI-574](https://docs.google.com/spreadsheets/d/1Zw2Aj3Si_YbPCuBXPZo_EzJNkz3oeswsx5LgSGrU6EA/edit#gid=1588822298)

The above also contains the sheet AWS Azure migration which show some more Project - Domain.

Table project, gitlab_namespace are pulled as is from gitlab

Table domain, team is extracted from various sources (csv, etc) and matching with gitlab namespace table. If not yet in gitlab they will have the field gitlab_ns_id is 0 which we wil auto create them later on.

These cross data table (like project_domain, team_domain) is updated using csv data, ...

Each table has a timestamp field auto update if there is update. Goal is to clean up stale data later on.

# To run

You need two csv files extracted from the sheet above and then run

See main.go for how to, and the order of data parser, command opt.

My example command is

```
go run --tags "sqlite_stat4 sqlite_foreign_keys sqlite_json" . -f ~/.dump-gitlab-project-data.json -db data/testdb.sqlite3 -a update-all
```

The json config file looks like

```
{
     "gitlabAPIBaseURL": "https://code.go1.com.au/api/v4",
     "gitlabToken": "Your Gitlab API Token",
     "SearchStr": ""
}
```

# Status

- Project - Domain use two csv files but might not be enough
- Team - Domain. Need manually enter
- Other pretty complete.

Next step is
- verify correctness of the project to be migrated lists
- write automation to migrate them
