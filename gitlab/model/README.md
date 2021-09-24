## What

It is a poor man ORM :). It makes use of the simple `sqlstruct` to save typing column name

Support golang idiomatic OOP or sort of.

Should be very fast as it does not put any heavy layer on top of standard sql driver. The sqlstruct uses a little of refect package but they are all lightweight.

## Usage

- One table, one file, one struct
- Copy the existing file to new one and
- Edit search/replace

Pay attention to the Update function you have to change the switch/case to match the real table column name.

The file should be short enough for easy to read/modify and adapt.

## Why not use sqlx ?

I don't know how to get column list in sqlx. I need it for the update and save typing the update stmt. Anyway it is less flexible and it enforce a new way to do things rather than sql standard.

Also sqlx is a bit more heavyweight (but not much really)
