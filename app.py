"""
Copyright (c) Francis Bui
Oct 6, 2020
"""

import csv
import re
import os
import pandas as pd
from datetime import datetime, timezone

from flask import Flask, render_template, request, url_for, session
from flaskext.mysql import MySQL
from passlib.hash import sha256_crypt
from werkzeug.utils import redirect

app = Flask(__name__)

the_key = os.urandom(16)
app.secret_key = the_key

mysql = MySQL()
app.config['MYSQL_DATABASE_USER'] = 'sql9383118'
app.config['MYSQL_DATABASE_PASSWORD'] = 'pLa9v4aRCh'
app.config['MYSQL_DATABASE_DB'] = 'sql9383118'
app.config['MYSQL_DATABASE_HOST'] = 'sql9.freemysqlhosting.net'
app.config['MYSQL_CURSOR CLASS'] = 'DictCursor'
mysql.init_app(app)


@app.route('/database')
def database():
    conn = mysql.connect()
    cur = conn.cursor()
    # cur.execute('''CREATE TABLE player (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(20))''')

    cur.execute(''' INSERT INTO player VALUES (1, 'Anthony')''')
    cur.execute(''' INSERT INTO player VALUES (2, 'Billy')''')
    mysql.connect().commit()
    cur.execute("SELECT name FROM player where id=2")
    results = cur.fetchone()
    print(results)
    return str(results[0])


@app.route('/')
def index():
    return render_template('index.html', todaydate=datetime.now().strftime('%A %B %d, %Y'))


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')


@app.route('/why')
def why():
    return render_template('why.html')


@app.route('/properties')
def properties():
    return render_template('properties.html')


@app.route('/apply')
def apply():
    return render_template('apply.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form['nm']
            password = request.form['np']
            with open('accounts.csv') as accounts:
                acc_pass = dict(filter(None, csv.reader(accounts)))

            if sha256_crypt.verify(password, acc_pass[username]):
                session['username'] = username
                print(session['username'])
                return render_template('dashboard.html',
                                       username=username,
                                       dashtodaydate=datetime.now().strftime('%b %d')
                                       )
            with open('logger.csv', "a") as log:
                log.write('\n' + datetime.now().strftime("%x, %X %p, ") +
                          datetime.now(timezone.utc).strftime('%X %Z, ') +
                          request.remote_addr)
            return render_template('login.html',
                                   taken='Password does not match. Please try again'
                                   )
    except KeyError:
        return render_template('login.html',
                               taken='Username does not exist'
                               )

    return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['nm']
        password = request.form['np']
        acc_pass = pd.read_csv('accounts.csv', skiprows=0)
        for i in acc_pass['username']:
            if i == username:
                return render_template('register.html',
                                       taken='Username is taken. Please try again.')

        if re.match(r"^(?=\S{12,40}$)(?=.*?\d)(?=.*?[a-z])"
                    r"(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])", password):
            with open('accounts.csv', "a") as accounts:
                accounts.write('\n' + username + ',' + sha256_crypt.hash(password))
                return redirect(url_for('login'))

        else:
            return render_template('register.html',
                                   taken='Password requirements: '
                                         '12 characters in length, '
                                         '1 uppercase character, '
                                         '1 lowercase character, '
                                         '1 number and '
                                         '1 special character.'
                                   )

    return render_template('register.html')


@app.route('/security', methods=['POST', 'GET'])
def updatepass():
    if 'username' not in session:
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form['nm']
        password = request.form['np']
        newpassword = request.form['nw']
        confpassword = request.form['cp']
        with open('CommonPassword.txt', 'r') as com_pass:
            com_pass = com_pass.read().split()
        with open('accounts.csv') as accounts:
            acc_pass = dict(filter(None, csv.reader(accounts)))

            if not sha256_crypt.verify(password, acc_pass[username]):
                return render_template('security.html',
                                       taken='Username and password '
                                             'does not match. Please try again.'
                                       )

            if sha256_crypt.verify(password, acc_pass[username]) and \
                    newpassword == confpassword and \
                    newpassword not in com_pass and \
                    re.match(r"^(?=\S{12,40}$)(?=.*?\d)(?=.*?[a-z])"
                             r"(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])", newpassword):
                acc_pass[username] = sha256_crypt.hash(newpassword)
                (pd.DataFrame.from_dict(data=acc_pass, orient='index')
                 .to_csv('accounts.csv', header=False))
                return render_template('dashboard.html',
                                       username=username,
                                       dashtodaydate=datetime.now().strftime('%b %d')
                                       )

            if sha256_crypt.verify(password, acc_pass[username]) and newpassword != confpassword:
                return render_template('security.html',
                                       taken='New passwords does not match. Please try again.'
                                       )

            return render_template('security.html',
                                   taken='Password requirements: '
                                         '12 characters in length, '
                                         '1 uppercase character, '
                                         '1 lowercase character, '
                                         '1 number and '
                                         '1 special character.'
                                   )

    return render_template('security.html',
                           username=session['username'])


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


# Dashboard
@app.route('/dashboard')  # experimental: probably should make it so if user 'is' in session
def dashboard():
    if 'username' not in session:
        return render_template('login.html')
    else:
        return render_template('dashboard.html',
                               username=session['username'],
                               dashtodaydate=datetime.now().strftime('%b %d'))


@app.route('/profile')
def profile():
    if 'username' not in session:
        return render_template('login.html')
    else:
        return render_template('profile.html',
                               username=session['username'])


@app.route('/billing')
def billing():
    if 'username' not in session:
        return render_template('login.html')
    else:
        return render_template('billing.html',
                               username=session['username'])


@app.route('/notifications')
def notifications():
    if 'username' not in session:
        return render_template('login.html')
    else:
        return render_template('notifications.html',
                               username=session['username'])


if __name__ == '__main__':
    app.run(debug=False)
