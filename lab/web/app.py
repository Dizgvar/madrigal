from flask import Flask, render_template

app = Flask(__name__)


# Главная страница со списком сессий
@app.route("/")
def index():
  # Пока создадим тестовые (фэйковые) сессии для примера
  mock_sessions = [
      {
          "id": "3b7c:1",
          "direction": "A>B",
          "packets_count": 42,
          "status": "Активна",
      },
      {
          "id": "3b7c:2",
          "direction": "B>A",
          "packets_count": 15,
          "status": "Активна",
      },
      {
          "id": "3b7c:3",
          "direction": "A>B",
          "packets_count": 128,
          "status": "Конфликт",
      },
  ]
  return render_template("index.html", sessions=mock_sessions)


if __name__ == "__main__":
  app.run(host="127.0.0.1", port=5000, debug=True)