# What is it
It is a automation system to allow us to do many automation tasks for gitlab repo, such as migrating a project from one namespace to other etc..

## Why?

Gitlab migrate project
- does not automate the migration of the docker image registry of the project. This implement that.
- does not migrate variables from the old groups to new groups, this project tries to do it in a safely manner.
- Gitlab offer managing users, but not domain, and team, it only has a generic `gitlab namespace` for managing groups. We can use the feature for the schema to allow more object kinds, such as `Domain - XXX` and `Team - XXX`. The entity relationship is outside of gitlab. This project data schema is modeled to support that and import form gitlab namespace data into it. See the folder `../models` for implementation.

## Goal.
- Build a pattern/framework that is easy to read and implement new adhoc functionality and maintenance.

## Dependencies
- Test run on linux system
- Require the tool `rclone` to sync the office 365 spreadsheet containing data for input.
  The setup credential of rclone must be done manually at the host where the program runs. See main.go for details.
- Require the `docker` cli installed. Docker should be able to pull/push to your gitlab registry; that means you have to setup authentication manually for the user who runs this program at the deployment host.

## Design
- Support cli run
- Support to spawn as a web server and api endpoint to get the data to various third party system
  The web GUI is a console type, to allow user to register, and login and run the command to aomplish tasks
- Support a cron task type to run dailly in background for the importing data from gitlab.
- Two stages:
     - Importing data from various sources, csv files, office 365 excel sheet so user can add, edit the input using the sheet.
     - Implement task in gitlab using the data
     - Answer api end point request to get the data for other system. (currently we fetch the list of root Domain in the name pattern `Domain - XXX`.)
- Practical, allow fast way to get input rather than mucking around fancy web form HTML etc, focus on writting code to acomplish the tasks and the quickest way.

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

The json config file looks like. See the complete schema in main.go.

```
{
     "gitlabAPIBaseURL": "https://code.go1.com.au/api/v4",
     "gitlabToken": "Your Gitlab API Token",
     "SearchStr": ""
}
```

In order to run the web console, first setup the dependecies (see above section) on a host for the user and just execute the binary using that user.

Then create the config file, the example is in main.go file.

Something like:
```
cat /home/azureuser/start-gitlab-tool.sh
#!/bin/sh

if [ "$1" = "stop" ]; then
  killall dump-gitlab-project
  exit 0
fi

cd $HOME/src/golang-tools/gitlab/projects/
if [ ! -f "dump-gitlab-project" ] || [ "$1" = "rebuild" ]; then
  go build --tags "sqlite_stat4 sqlite_foreign_keys sqlite_json" .
fi
nohup ./dump-gitlab-project -f ~/.go1-gitlab-project.json -db 'data/testdb.sqlite3?busy_timeout=15000' -a StartWebGUI &
```
and in /etc/rc.local
```
sudo -u azureuser /home/azureuser/start-gitlab-tool.sh
```

# Status

- Project - Domain use two csv files but might not be enough
- Team - Domain. Need manually enter
- Other pretty complete.
