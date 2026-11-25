---
group: Added
---
role `compose_app`: the nightly export timer (`compose_app_export_timer`) also copies and verifies what is not a database server's: `compose_app_export_files` takes `sqlite` entries (every file a glob matches, through SQLite's online backup, `PRAGMA integrity_check` ok and a table in the copy) and `tree` entries (a gzip tar minus exclusions); a glob that matches nothing or an empty tree fails the run, and a manifest with no database job needs no compose file. The forge (database and repositories), the feed reader (every account's database), the DNS server (its configuration directory), the notifier and chat front door (their SQLite files) and the status hub (activity store and state directory) now have a scheduled export.
