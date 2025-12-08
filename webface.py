from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    Markup,
    escape,
    flash,
)
import functools
import string
import random
import datetime
from sqlitewrap import SQLite
from werkzeug.security import generate_password_hash, check_password_hash
from sqlite3 import IntegrityError

app = Flask(__name__)
app.secret_key = b"totoj e zceLa n@@@hodny retezec nejlep os.urandom(24)"
app.secret_key = b"x6\x87j@\xd3\x88\x0e8\xe8pM\x13\r\xafa\x8b\xdbp\x8a\x1f\xd41\xb8"


def url_s_gen():
    x = ''
    for i in range(6):
        x = f'{x}{random.choice(string.ascii_letters + string.digits)}'
    url_short = x
    return url_short


def prihlasit(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        if "user" in session:
            return function(*args, **kwargs)
        else:
            return redirect(url_for("login", url=request.path))

    return wrapper


@app.route("/", methods=["GET"])
def base():
    return render_template("base.html")


@app.route("/", methods=["POST"])
def base_post():
    print("f")
    url=""
    short_url=request.form.get("url_short")
    print(short_url)
    if short_url:
        with SQLite('data.sqlite') as cur:
            try:
                url = cur.execute('SELECT long_url FROM url WHERE short_url = ?',[short_url]).fetchone()[0]
            except TypeError:
                flash(f'address {short_url} does not exist', 'error')
            if url:
                return redirect(url)
    return render_template('base.html')


@app.route('/url_short', methods=['GET'])
def url_short():
    if 'user' in session:
        with SQLite('data.sqlite') as cur:
            u_id = cur.execute('SELECT id FROM user WHERE username = ?',[session['user']]).fetchone()[0]
            response = cur.execute('SELECT long_url, short_url FROM url WHERE u_id = ?',[u_id]).fetchall()
        return render_template('url_short.html', response=response)
    else:
        return render_template('url_short.html')


@app.route("/url_short/", methods=['POST'])
def url_short_post():
    url_long = ""
    url_short=""
    url_long = request.form.get("url_long")
    response = []
    if url_long:
        while True:
            url_short = url_s_gen()
            if 'user' not in session:
                    try:
                        with SQLite('data.sqlite') as cur:
                                cur.execute('INSERT into url (long_url, short_url) VALUES(?, ?)',[url_long, url_short])
                        break
                    except IntegrityError:
                        pass
            else:
                try:    
                    with SQLite('data.sqlite') as cur:
                        u_id = cur.execute('SELECT id FROM user WHERE username = ?',[session['user']]).fetchone()[0]
                        cur.execute('INSERT into url (long_url, short_url, u_id) VALUES(?, ?, ?)',[url_long, url_short, u_id])
                        response = cur.execute('SELECT long_url, short_url FROM url WHERE u_id = ?',[u_id]).fetchall()
                    break
                except IntegrityError:
                    pass
    else:
        if 'user' in session:
            with SQLite('data.sqlite') as cur:
                u_id = cur.execute('SELECT id FROM user WHERE username = ?',[session['user']]).fetchone()[0]
                response = cur.execute('SELECT long_url, short_url FROM url WHERE u_id = ?',[u_id]).fetchall()
    return render_template('url_short.html', response=response, short_url=url_short)



@app.route('/<short_url>')
def jmp(short_url):
    with SQLite('data.sqlite') as cur:
        url = cur.execute('SELECT long_url FROM url WHERE short_url = ?',[short_url]).fetchone()[0]
    return redirect(url)



@app.route('/login/', methods=["GET"])
def login():
    if 'user' not in session:
        return render_template('login.html')
    return render_template('logout.html')


@app.route('/login/', methods=["POST"])
def login_post():
    username = request.form.get('username','')
    password = request.form.get('password','')
    url = request.args.get('url', '')
    with SQLite('data.sqlite') as cur:
        response = cur.execute('SELECT username, password FROM user WHERE username = ?',[username]).fetchone()
        if response:
            username, pass_hash = response
            if check_password_hash(pass_hash, password):
                session['user'] = username
                flash('login successful', 'success')
                if url:
                    return redirect(url)
                else:
                    return redirect(url_for('base'))
        flash('incorrect username or password', 'error')
        return redirect(url_for('login', url=url))
                

@app.route('/logout/')
def logout():
    session.pop('user', None)
    return redirect(url_for('base'))


@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username', '')
    password_0 = request.form.get('password_0', '')
    password_1 = request.form.get('password_1', '')
    if password_0 != password_1:
        flash('passwords do not match', 'error')
        return redirect('register')        
    pass_hash = generate_password_hash(password_0)
    try:
        with SQLite('data.sqlite') as cur:
            cur.execute('INSERT into user (username, password) VALUES (?, ?)', [username, pass_hash])
        flash(f'user {username} was successfully registered', 'success')
    except IntegrityError:
        flash(f'user {username} already exists', 'error')
    return redirect(url_for('register'))


@app.route('/register', methods=['GET'])
def register():
    if 'user' not in session:
        return render_template("register.html")
    else:
        return render_template('logout.html')