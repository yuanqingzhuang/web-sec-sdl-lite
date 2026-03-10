from flask import Flask, request, render_template, redirect, url_for
import os
import sqlite3

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "demo.db")
DATA_DIR = os.path.join(BASE_DIR, "data")

comments_store = []


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)
    cur.execute("DELETE FROM users")
    cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    cur.execute("INSERT INTO users (username, password) VALUES ('test', 'test123')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    result = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # 故意保留：SQL 拼接
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
            if row:
                result = f"Login success: {row[1]}"
            else:
                result = "Login failed"
        except Exception as e:
            result = f"Database error: {e}"
        finally:
            conn.close()

        return render_template("login.html", result=result, query=query)

    return render_template("login.html", result=result, query="")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # 故意保留：后面模板里使用 |safe
    return render_template("search.html", q=q)


@app.route("/comment", methods=["GET", "POST"])
def comment():
    if request.method == "POST":
        author = request.form.get("author", "")
        content = request.form.get("content", "")
        comments_store.append({
            "author": author,
            "content": content
        })
        return redirect(url_for("comments"))
    return render_template("comment.html")


@app.route("/comments")
def comments():
    return render_template("comments.html", comments=comments_store)


@app.route("/read")
def read_file():
    name = request.args.get("name", "test.txt")
    if not name :
        name = "test.txt"
    # 故意保留：路径拼接
    file_path = os.path.join(DATA_DIR, name)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        content = f"Error: {e}"

    return render_template("read.html", name=name, content=content)


@app.route("/exec", methods=["GET", "POST"])
def exec_demo():
    code = ""
    result = ""
    if request.method == "POST":
        code = request.form.get("code", "")
        try:
            # 故意保留：危险函数调用
            result = str(eval(code))
        except Exception as e:
            result = f"Error: {e}"
    return render_template("exec.html", code=code, result=result)


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    test_file = os.path.join(DATA_DIR, "test.txt")
    if not os.path.exists(test_file):
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("This is a demo file.\nUsed for path traversal testing.")
    init_db()
    app.run(debug=True)
