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
import sqlite3
from passlib.hash import sha256_crypt
from werkzeug.utils import redirect

app = Flask(__name__)

the_key = os.urandom(16)
app.secret_key = the_key


@app.route('/database')
def database():
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        # cur.execute("create table Employees (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, address TEXT NOT NULL)")
        # cur.execute('''INSERT INTO employees (name, email, address) VALUES ('frankie', 'frankie@gmail.com', '123 Hello Dr')''')
        cur.execute('''Select firstname from user WHERE id=1''')
        # con.commit()
        results = cur.fetchone()
        print(results)
        cur.execute('''Select dob from user WHERE id=1''')
        name = cur.fetchone()
        con.close()
        return render_template('database.html', results=results[0], name=name[0])


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
            email = request.form['nm']
            password = request.form['np']
            # with open('accounts.csv') as accounts:
            #     acc_pass = dict(filter(None, csv.reader(accounts)))

            with sqlite3.connect("database.db") as con:
                cur = con.cursor()
            cur.execute('SELECT email FROM user where email=?', (email,))  # prevent SqlInject
            email_check = cur.fetchone()
            cur.execute('SELECT password FROM user where email=?', (email,))  # prevent SqlInject
            password_check = cur.fetchone()
            # con.close()

            if sha256_crypt.verify(password, password_check[0]):
                cur.execute('SELECT firstname FROM user where email=?', (email,))  # prevent SqlInject
                firstname = cur.fetchone()
                cur.execute('SELECT lastname FROM user where email=?', (email,))  # prevent SqlInject
                lastname = cur.fetchone()
                username = firstname[0] + " " + lastname[0]
                session['username'] = email_check[0]
                print(session['username'])
                con.close()
                return render_template('dashboard.html',
                                       username=username,
                                       dashtodaydate=datetime.now().strftime('%b %d')
                                       )
            con.close()  # closing database if verification fails

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
    # Get data from the registration form
    if request.method == 'POST':
        firstname = request.form['fn']
        lastname = request.form['ln']
        unit = request.form['ut']
        email = request.form['em']
        password = request.form['np']
        primarynumber = request.form['pn']
        dob = request.form['bd']

        # Checks if email is already taken
        with sqlite3.connect("database.db") as con:
            cur = con.cursor()
        cur.execute('SELECT 1 FROM user where email=?', (email,))  # prevent SqlInject
        email_check = cur.fetchone()
        print(email_check)
        if email_check is not None:
            print('email is taken')
            con.close()
            return render_template('register.html',
                                   taken='Email is already registered. Please try again.')

        # Validate the user's new password
        if re.match(r"^(?=\S{12,40}$)(?=.*?\d)(?=.*?[a-z])"
                    r"(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])", password):
            password = sha256_crypt.hash(password)
            cur.execute(
                '''INSERT INTO user(firstname, lastname, dob, email, primarynumber, password, unit) VALUES (?,?,?,?,?,?,?)''',
                (firstname, lastname, dob, email, primarynumber, password, unit))
            con.commit()
            print('added new user to the database')
            con.close()
            return redirect(url_for('login'))

        # New password length or combination is not safe
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
    app.run(debug=True)
