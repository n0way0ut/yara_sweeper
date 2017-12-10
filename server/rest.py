from flask import Flask, render_template, request, jsonify
import json
import sqlite3

app = Flask(__name__)

columns = [
  {
    "field": "timestamp",  
    "title": "Timestamp", 
    "sortable": True,
  },
  {
    "field": "hostname",
    "title": "Hostname",
    "sortable": True,
  },
  {
    "field": "rulename",
    "title": "Rule name",
    "sortable": True,
  },
  {
    "field": "desc",
    "title": "Rule Desc.",
    "sortable": True,
  },
  {
    "field": "filename",
    "title": "File name",
    "sortable": True,
  },
  {
    "field": "sha256",
    "title": "File hash",
    "sortable": False,
  },
  {
    "field": "pid",
    "title": "Pid",
    "sortable": False,
  },
  {
    "field": "proc",
    "title": "Process",
    "sortable": True,
  }
]

def store_db(json):
    
    db = sqlite3.connect('data.db')
    cursor = db.cursor()
    for match in json:
        cursor.execute('''INSERT INTO matches(rulename, desc, filename, sha256, pid, proc, hostname) 
                            VALUES(?,?,?,?,?,?,?)''', 
                                                     ( match['rulename'],
                                                       match['desc'],
                                                       match['filename'] if 'filename' in match else '-',
                                                       match['sha256']  if 'sha256' in match else '-',
                                                       match['pid'] if 'pid' in match else '-',
                                                       match['proc'] if 'proc' in match else '-',
                                                       match['hostname'] ) 
                     )

        db.commit()

    db.close()


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def get_db():
    
    db = sqlite3.connect('data.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM matches WHERE timestamp >= datetime('now','-1 day')''')
    rows = cursor.fetchall()
    data = []
    for r in rows:
        data.append(dict_factory(cursor, r))
    db.close()
    return data


@app.route('/post_match', methods = ['POST'])
def post_match():
    
    if(request.is_json):
        content = request.get_json()
        store_db(content)
        return ''
    else:
        return ''


@app.route('/refresh')
def refresh():

    data = get_db()
    return jsonify(data)


@app.route('/')
def index():

    data = get_db()

    return render_template("table.html", data=data, columns=columns, title='Yara Sweeper Dashboard')


if __name__ == '__main__':
  app.run(port=8080, debug=False)
