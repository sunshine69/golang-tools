# data source

- use gitlab golang sdk to pull data and update the local db to refect what we want
- also use various sources to get Project - Domain relationship

From ticket [DNI-574](https://docs.google.com/spreadsheets/d/1Zw2Aj3Si_YbPCuBXPZo_EzJNkz3oeswsx5LgSGrU6EA/edit#gid=1588822298)

The above also contains the sheet AWS Azure migration which show some more Project - Domain.

# Status

- Project - Domain use two csv files but might not be enough
- Team - Domain. Need manually enter
- Other pretty complete.

Next step is
- verify correctness of the project to be migrated lists
- write automation to migrate them
