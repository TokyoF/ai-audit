"""Deliberately-vulnerable Flask app for the AI-auditor lab. INTENTIONAL SQLi."""
import sqlite3
from flask import Flask, request, Response

app = Flask(__name__)
DB = "/tmp/shop.db"


def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER, name TEXT, price TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)")
    cur.execute("DELETE FROM products")
    cur.execute("DELETE FROM users")
    cur.executemany(
        "INSERT INTO products VALUES (?,?,?)",
        [(1, "Laptop", "999"), (2, "Phone", "599"), (3, "Tablet", "399")],
    )
    cur.executemany(
        "INSERT INTO users VALUES (?,?,?)",
        [(1, "admin", "S3cr3tAdminP@ss"), (2, "john", "john123")],
    )
    con.commit()
    con.close()


@app.after_request
def fake_banner(resp):
    # Intentional: advertise an old, vulnerable server for nmap/nikto fingerprinting.
    resp.headers["Server"] = "Apache/2.2.8 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/5.2.4"
    return resp


@app.route("/")
def index():
    return Response(
        "<h1>ACME Corp Store</h1>"
        "<ul>"
        "<li><a href='/product?id=1'>Product 1</a></li>"
        "<li><a href='/product?id=2'>Product 2</a></li>"
        "<li><a href='/login'>Login</a></li>"
        "</ul>",
        mimetype="text/html",
    )


@app.route("/robots.txt")
def robots():
    # Intentional: leaks hidden admin path.
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /backup\n", mimetype="text/plain")


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    con = sqlite3.connect(DB)
    cur = con.cursor()
    # INTENTIONAL SQL INJECTION: raw string concatenation.
    query = "SELECT id, name, price FROM products WHERE id = " + pid
    try:
        rows = cur.execute(query).fetchall()
    except Exception as exc:
        # INTENTIONAL: verbose SQL error leak.
        return Response("SQL error: " + str(exc) + "<br>Query: " + query, status=500, mimetype="text/html")
    finally:
        con.close()
    body = "<h1>Products</h1>"
    for r in rows:
        body += "<div>ID %s - %s - $%s</div>" % (r[0], r[1], r[2])
    return Response(body, mimetype="text/html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd = request.form.get("password", "")
        con = sqlite3.connect(DB)
        cur = con.cursor()
        # INTENTIONAL SQL INJECTION in auth.
        query = "SELECT id, username FROM users WHERE username = '" + user + "' AND password = '" + pwd + "'"
        try:
            row = cur.execute(query).fetchone()
        except Exception as exc:
            return Response("SQL error: " + str(exc) + "<br>Query: " + query, status=500, mimetype="text/html")
        finally:
            con.close()
        if row:
            return Response("<h1>Welcome, %s!</h1>" % row[1], mimetype="text/html")
        return Response("<h1>Invalid credentials</h1>", status=401, mimetype="text/html")
    return Response(
        "<h1>Login</h1>"
        "<form method='post' action='/login'>"
        "Username: <input name='username'><br>"
        "Password: <input name='password' type='password'><br>"
        "<input type='submit' value='Login'>"
        "</form>",
        mimetype="text/html",
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=80)
