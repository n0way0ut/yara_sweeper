#!/bin/bash
sqlite3 data.db  "CREATE TABLE matches(rulename text, desc text, filename text, sha256 text, pid text, proc text, hostname text, timestamp DATETIME DEFAULT (datetime('now','localtime')));"

if [ $? -eq 0 ]; then
    echo "[*] done.."
else
    echo "[!] fail.."
fi

