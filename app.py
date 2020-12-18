"""
Copyright (c) Francis Bui
Oct 6, 2020
"""

import csv
import re
from datetime import datetime, timezone

import pandas as pd
from passlib.hash import sha256_crypt
from flask import Flask, render_template, request, url_for, session
from werkzeug.utils import redirect

app = Flask(__name__)

app.secret_key = 'thisismysecretkey'


@app.route('/')
def index():
    """
    Homepage
    Will call and render the homepage template as well as return the datetime.
    Additionally will return the name provided if one is used in the url parameter
    :return: webpage and datetime function
    """
    return render_template('index.html', todaydate=datetime.now().strftime('%c'))


@app.route('/aboutus')
def aboutus():
    """
    About Us page
    Simply return the aboutus.html page
    :return: webpage
    """
    return render_template('aboutus.html')


@app.route('/properties')
def properties():
    """
    Properties page
    Simply return the properties.html page
    :return: webpage
    """
    return render_template('properties.html')


@app.route('/apply')
def apply():
    """
    Apply page
    Simply return the apply.html page
    :return: webpage
    """
    return render_template('apply.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page
    Authenticate and allows user to login to their dashboard
    :return: webpage
    """
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
    """
    Register page
    Allows user to create an account
    :return: webpage
    """

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


@app.route('/updatepass', methods=['POST', 'GET'])
def updatepass():
    """
    Update password page
    Allows user change their password
    only if they are already logged in
    :return: webpage
    """
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
                return render_template('updatepass.html',
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
                return render_template('updatepass.html',
                                       taken='New passwords does not match. Please try again.'
                                       )

            return render_template('updatepass.html',
                                   taken='Password requirements: '
                                         '12 characters in length, '
                                         '1 uppercase character, '
                                         '1 lowercase character, '
                                         '1 number and '
                                         '1 special character.'
                                   )

    return render_template('updatepass.html')


@app.route('/logout')
def logout():
    """
    Logout function
    Ends user's session and redirects them
    back to the homepage
    :return: redirection
    """
    session.pop('username', None)
    return redirect(url_for('index'))


# Dashboard

@app.route('/profile')
def profile():
    return render_template('profile.html')


@app.route('/billing')
def billing():
    return render_template('billing.html')


if __name__ == '__main__':
    app.run(debug=True)
