import sys
from pathlib import Path

# Добавляем корень проекта в системный путь поиска модулей
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir))

from flask import Flask, render_template, abort
from lab import api

app = Flask(__name__)

# Инициализируем проект через фасад и импортируем файл стенда
PROJECT_PATH = Path("data/stand_project")
STAND_FILE = Path("data/stand/rec01.pcapng")

project = api.open_project(PROJECT_PATH)
if STAND_FILE.exists():
    api.import_capture(project, STAND_FILE)


@app.route("/")
def index():
    sessions_list = []
    for source_id in project.sources:
        sessions = api.list_sessions(project, source_id)
        for s in sessions:
            sessions_list.append({
                "id": getattr(s, "session_id", str(s)),
                "direction": getattr(s, "direction", "A>B"),
                "packets_count": len(getattr(s, "packets", [])),
                "status": "Активна"
            })
            
    return render_template("index.html", sessions=sessions_list)


@app.route("/session/<path:session_id>")
def session_detail(session_id):
    target_session = None
    target_source_id = None
    
    for source_id, data in project.sources.items():
        for s in data["sessions"]:
            if getattr(s, "session_id", str(s)) == session_id:
                target_session = s
                target_source_id = source_id
                break
        if target_session:
            break
            
    if not target_session:
        abort(404)
        
    direction = getattr(target_session, "direction", "A>B")
    
    try:
        packets = api.trace(project, session_id, direction, 0, 100)
    except Exception:
        packets = []
        
    return render_template("session.html", session=target_session, packets=packets)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)