# Copyright (c) 2020, Pensando Systems
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# Author: Toby Makepeace <toby@pensando.io>

"""
Pensando Systems Tap As A Server

The tool is just to provide a demo of the capabilities of building
Tap as a Service for the network/compute consumers/business units.

|Instructions/Usage statement including parameters|

This software is provided without support, warranty, or guarantee. Use at your own risk.
"""

''' A one-line docstring '''
# TODO: Write some code after this block comment
# FIXME: What needs to be fixes
# NOTE: a simple refernce note.

"""
A multiline docstring. 
Keyword arguments: 
parameter -- an example parameter (default False) 
"""

"""
Each section of web code needs to validate the loggedin session cookie. 
example:
    if 'loggedin' in session:
        <then>
    return redirect(url_for('login'))

if you need to do a admin password reset from to get the output needed to be loaded in the DB
from a python console. 
> password1 = generate_password_hash('Pensando0$')
> print password1
from werkzeug.security import generate_password_hash, check_password_hash
print(generate_password_hash('test'))
"""

# TODO: The threading and time options will be needed when i create the background jobs.
import threading
import time
import requests
import sys
import pymysql
import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, flash, redirect, url_for, session, request,  send_from_directory
from wtforms import Form, StringField,  IntegerField, PasswordField, BooleanField, validators, SelectField
from wtforms.fields.html5 import EmailField
from werkzeug.security import generate_password_hash, check_password_hash
from configparser import ConfigParser

# TODO: once run by the installer, change to /home/tmakepeace/Tapasaservice
sys.path.append("/app/PenTapasaService")

try:
    from variables import *
except ImportError:
    """
    As the variables file does not exist, create a file with defaults.
    Wait 3 seconds and then import the values. 
    """
    f = open("variables.py", "w")
    f.write("""
# The master variable file 
# file can be edited directly after initial cretion 
#

# the host the webservice is hosted on, FQDN or IP is required.
# 0.0.0.0 for all interfaces.
webhost = '0.0.0.0'

# the port the webservice is hosted on, default flask is 5000.
webport = '5000' 

# the host the MYSQL database is hosted on, FQDN or IP is required.
# 127.0.0.1 for local or docker config.
host = '127.0.0.1' 
 
# the default port that the MySQL database is running on. 
port = 3306 
 
# The user to connect to the MySQL database. 
user = 'Pensando' 
 
# The Password of the user connecting to the MySQL database. 
passwd = 'Pensando0$' 
 
# The Name of the database the data is to be store in. 
db = 'TapAsAService' 

# The web service idle timeout for logged in users. 
webtimeout = 5 


""")

    f.close()
    time.sleep(3)
    sys.exit(0)

try:
    f = open("psm.cfg")
except IOError:
    f = open("psm.cfg", "w")
    f.write("""
    [global]
    ipman = 
    adminuser = 
    adminpwd = 
    cookiekey = 
    expiry = 'Sun, 03 Jan 2099 15:02:35 GMT'

        """)
finally:
    f.close()
    time.sleep(3)



# TODO: not sure if this is needed. need to see where else device or newdevice are called.
"""
try:
    from device import *
except ImportError:
    from newdevice import *
"""

app = Flask(__name__, static_url_path='/static')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'PensandoTapAsAService'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
# TODO: need to change the expiry time back to 5 minutes.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=webtimeout)

conn = pymysql.connect(host=host, port=port, user=user, passwd=passwd, db=db)

# Note: The web structure is defined from this point onwards.

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico')


# Note:  All the pages that require an account login to manage
@app.route('/login/', methods=['GET', 'POST'])
def login():
    ''' user login page function '''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        upassword = request.form['password']
        # Check if account exists using MySQL
        cur = conn.cursor()
        cur.execute('SELECT * FROM UserAccounts WHERE username = %s;', username)
        # Fetch one record and return result
        account = cur.fetchone()
        # If account exists in accounts table in out database
        #        if account:
        if account is None:
            msg = 'Incorrect username/password'
            flash(msg, 'warning')
            cur.close()
            return redirect(url_for('login'))

        if check_password_hash(account[2], upassword) is True:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]
            session['admin'] = False
            session.permanent = True
            # Redirect to home page
            cur2 = conn.cursor()
            cur2.execute(" update UserAccounts set  updatedate =now() where id =%s;",
                         ([session['id']]))
            ## commit and close ##
            conn.commit()
            cur2.close()
            cur.close()
            return redirect(url_for('home'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password'
            flash(msg, 'warning')
            cur.close()
            return redirect(url_for('login'))
        #  return redirect(url_for('login'))
        # Show the login form with message (if any)

    return render_template('loginindex.html')
    #, msg=msg)


@app.route('/adminlogin/', methods=['GET', 'POST'])
def adminlogin():
    # FIX: the error messages are not being displayed.
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        upassword = request.form['password']
        # Check if account exists using MySQL
        cur = conn.cursor()
        cur.execute('SELECT * FROM AdminAccounts WHERE username = %s;', username)
        # Fetch one record and return result
        account = cur.fetchone()
        # If account exists in accounts table in out database
        #        if account:
        if account is None:
            msg = 'Incorrect username/password'
            flash(msg, 'warning')
            cur.close()
            return redirect(url_for('adminlogin'))

        if check_password_hash(account[2], upassword) is True:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]
            session['admin'] = True
            session.permanent = True
            cur2 = conn.cursor()
            cur2.execute(" update AdminAccounts set updatedate =now() where id =%s;",
                         ([session['id']]))
            ## commit and close ##
            conn.commit()
            cur2.close()
            cur.close()
            # Redirect to home page
            return redirect(url_for('adminhome'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password'
            flash(msg, 'warning')
            cur.close()
            return redirect(url_for('adminlogin'))
        #  return redirect(url_for('login'))
        # Show the login form with message (if any)

    return render_template('adminloginindex.html')
    #, msg=msg)

"""
LOGGED IN SECTION
"""

@app.route('/changepwd', methods=['GET', 'POST'])
def changepwd():
    ''' Users change password code  called for both the admin users and consumer users. '''
    if 'loggedin' in session:
        form = ChangePwd(request.form)
        if request.method == 'POST' and form.validate():
            currentpwd = form.currentpwd.data
            newpwd = form.newpwd.data
            checkpwd = form.checkpwd.data
            if session['admin'] == True:
                if newpwd == checkpwd:
                    cur = conn.cursor()
                    cur.execute("SELECT password FROM AdminAccounts WHERE id = %s;", [session['id']])
                    account = cur.fetchone()
                    if check_password_hash(account[0], currentpwd) == True:
                        updatepwd = generate_password_hash(newpwd)
                        cur2 = conn.cursor()
                        cur2.execute(" update AdminAccounts set password = %s , updatedate =now() where id =%s;", (updatepwd, [session['id']]))
                        ## commit and close ##
                        conn.commit()
                        cur2.close()
                        session.pop('loggedin', None)
                        session.pop('id', None)
                        session.pop('username', None)
                        session.pop('admin', None)
                        cur.close()
                        return redirect(url_for('home'))
                        #return render_template('changepwd.html', form=form)
                    else:
                        msg = 'Existing Passwords do not match'
                        flash(msg, 'warning')
                        cur.close()
                        return redirect(url_for('changepwd'))

                else:
                    msg = 'New Passwords do not match'
                    flash(msg, 'warning')
                    return redirect(url_for('changepwd'))
            elif session['admin'] == False:
                if newpwd == checkpwd:
                    cur = conn.cursor()
                    cur.execute("SELECT password FROM UserAccounts WHERE id = %s;", [session['id']])
                    account = cur.fetchone()
                    if check_password_hash(account[0], currentpwd) == True:
                        updatepwd = generate_password_hash(newpwd)
                        cur2 = conn.cursor()
                        cur2.execute(" update UserAccounts set password = %s , updatedate =now() where id =%s;",
                                     (updatepwd, [session['id']]))
                        ## commit and close ##
                        conn.commit()
                        cur2.close()
                        session.pop('loggedin', None)
                        session.pop('id', None)
                        session.pop('username', None)
                        session.pop('admin', None)
                        cur.close()
                        return redirect(url_for('home'))
                        #return render_template('changepwd.html', form=form)
                    else:
                        msg = 'Existing Passwords do not match'
                        flash(msg, 'warning')
                        cur.close()
                        return redirect(url_for('changepwd'))

                else:
                    msg = 'New Passwords do not match'
                    flash(msg, 'warning')
                    return redirect(url_for('changepwd'))

        return render_template('changepwd.html', form=form)

    return redirect(url_for('login'))

@app.route('/adminchangepwd', methods=['GET', 'POST'])
def adminchangepwd():
    ''' Users change password code  called for both the admin users and consumer users. '''
    if 'loggedin' in session:
        form = ChangePwd(request.form)
        if request.method == 'POST' and form.validate():
            currentpwd = form.currentpwd.data
            newpwd = form.newpwd.data
            checkpwd = form.checkpwd.data
            if session['admin'] == True:
                if newpwd == checkpwd:
                    cur = conn.cursor()
                    cur.execute("SELECT password FROM AdminAccounts WHERE id = %s;", [session['id']])
                    account = cur.fetchone()
                    if check_password_hash(account[0], currentpwd) == True:
                        updatepwd = generate_password_hash(newpwd)
                        cur2 = conn.cursor()
                        cur2.execute(" update AdminAccounts set password = %s , updatedate =now() where id =%s;", (updatepwd, [session['id']]))
                        ## commit and close ##
                        conn.commit()
                        cur2.close()
                        session.pop('loggedin', None)
                        session.pop('id', None)
                        session.pop('username', None)
                        session.pop('admin', None)
                        cur.close()
                        return redirect(url_for('home'))
                        #return render_template('changepwd.html', form=form)
                    else:
                        msg = 'Existing Passwords do not match'
                        flash(msg, 'warning')
                        cur.close()
                        return redirect(url_for('changepwd'))

                else:
                    msg = 'New Passwords do not match'
                    flash(msg, 'warning')
                    return redirect(url_for('changepwd'))
            elif session['admin'] == False:
                if newpwd == checkpwd:
                    cur = conn.cursor()
                    cur.execute("SELECT password FROM UserAccounts WHERE id = %s;", [session['id']])
                    account = cur.fetchone()
                    if check_password_hash(account[0], currentpwd) == True:
                        updatepwd = generate_password_hash(newpwd)
                        cur2 = conn.cursor()
                        cur2.execute(" update UserAccounts set password = %s , updatedate =now() where id =%s;",
                                     (updatepwd, [session['id']]))
                        ## commit and close ##
                        conn.commit()
                        cur2.close()
                        session.pop('loggedin', None)
                        session.pop('id', None)
                        session.pop('username', None)
                        session.pop('admin', None)
                        cur.close()
                        return redirect(url_for('home'))
                        #return render_template('changepwd.html', form=form)
                    else:
                        msg = 'Existing Passwords do not match'
                        flash(msg, 'warning')
                        cur.close()
                        return redirect(url_for('changepwd'))

                else:
                    msg = 'New Passwords do not match'
                    flash(msg, 'warning')
                    return redirect(url_for('changepwd'))

        return render_template('adminchangepwd.html', form=form)

    return redirect(url_for('login'))


@app.route('/login/logout')
def logout():
    ''' Remove session data, this will log the user out and return them to the login page '''
    if session['admin'] == True:
        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('username', None)
        session.pop('admin', None)
        # Redirect to login page
        return redirect(url_for('adminlogin'))
    elif session['admin'] == False:
        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('username', None)
        session.pop('admin', None)
        # Redirect to login page
        return redirect(url_for('login'))
    

"""
MANAGED USER SECTION
"""	
    
@app.route("/manageadmin")
def manageadmin():
    """
    Display the list of admin user accounts available
    checks to make sure the user logged in is a admin user is repeated in every section
    """
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        result = cur.execute("select id, username , email, updatedate  from AdminAccounts;")
        results = cur.fetchall()
        #print(results)
        if result > 0:
            cur.close()
            return render_template('manageadmin.html', results=results)
        else:
            msg = 'No Users registered'
            flash(msg, 'warning')
            cur.close()
            return render_template('manageadmin.html', results=results)

    return redirect(url_for('adminlogin'))

@app.route("/manageusers")
def manageusers():
    ''' Display all the consumer users allowing you to add/edit/remove accounts '''
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        result = cur.execute("select id, username , email, updatedate  from UserAccounts;")
        results = cur.fetchall()
        #print(results)
        if result > 0:
            cur.close()
            return render_template('manageusers.html', results=results)
        else:
            msg = 'No Users registered'
            flash(msg, 'warning')
            cur.close()
            return render_template('manageusers.html', msg=msg)

    return redirect(url_for('adminlogin'))

"""
ADMIN MANAGER SECTION
"""

@app.route("/addadmin", methods=['GET', 'POST'])
def addadmin():
    """ 
    Add Admin section,  
    """
    if 'loggedin' in session and session['admin'] == True:
        form = AddAdminForm(request.form)
        if request.method == 'POST' and form.validate():
            username = form.username.data
            useremail = form.useremail.data
            userpassword = form.userpassword.data
            passworduser = generate_password_hash(userpassword)

            ## cursor ##
            cur = conn.cursor()
            cur.execute(
                " INSERT INTO `AdminAccounts` (`username`, `email`,`password`,`updatedate`)VALUES ( %s,%s,%s, now()) ",
                (username, useremail, passworduser))

            ## commit and close ##
            conn.commit()
            cur.close()

            flash('User Added', 'success')
            return redirect(url_for('manageadmin'))

        #        return render_template('adduser.html')
        return render_template('addadmin.html', form=form)
    return redirect(url_for('adminlogin'))

@app.route("/adduser", methods=['GET', 'POST'])
def adduser():
    if 'loggedin' in session and session['admin'] == True:
        form = AddAdminForm(request.form)
        if request.method == 'POST' and form.validate():
            username = form.username.data
            useremail = form.useremail.data
            userpassword = form.userpassword.data
            passworduser = generate_password_hash(userpassword)

            ## cursor ##
            cur = conn.cursor()
            cur.execute(
                " INSERT INTO `UserAccounts` (`username`, `email`,`password`,`updatedate`)VALUES ( %s,%s,%s, now()) ",
                (username, useremail, passworduser))

            ## commit and close ##
            conn.commit()
            cur.close()

            flash('User Added', 'success')
            return redirect(url_for('adduser'))

        #        return render_template('adduser.html')
        return render_template('adduser.html', form=form)
    return redirect(url_for('adminlogin'))


@app.route("/deleteadmin/<string:id>/", methods=['GET', 'POST'])
def deleteadmin(id):
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        cur.execute(" SELECT id, `username`,`email` FROM `AdminAccounts` where id = %s;", [id])
        results = cur.fetchone()
        cur.execute(" SELECT count(id) as count FROM `AdminAccounts` ;")
        results1 = cur.fetchone()

        form = DeleteAdminForm(request.form)
        form.username.data = results[1]
        form.useremail.data = results[2]
        countid = results1[0]

        if request.method == 'POST' and form.validate():
            #            username = request.form['username']
            #            useremail = request.form['email']
            countid = int(countid)
            ## cursor ##
            if countid == 1:
                flash('Master admin can not be deleted', 'info')
                cur.close()
                return redirect(url_for('manageadmin'))
            else:
                #cur = conn.cursor()
                cur.execute(" Delete from `AdminAccounts` where id = %s", [id])
                ## commit and close ##
                conn.commit()
                cur.close()

                flash('Admin deleted', 'success')
                return redirect(url_for('manageadmin'))
        cur.close()
        return render_template('deleteadmin.html', form=form)
    return redirect(url_for('adminlogin'))

@app.route("/deleteuser/<string:id>/", methods=['GET', 'POST'])
def deleteuser(id):
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        result = cur.execute(" SELECT id, `username`,`email` FROM `UserAccounts` where id = %s;", [id])
        results = cur.fetchone()
        result1 = cur.execute(" SELECT count(id) as count FROM `UserAccounts` ;")
        results1 = cur.fetchone()

        form = DeleteAdminForm(request.form)
        form.username.data = results[1]
        form.useremail.data = results[2]
        countid = results1[0]

        if request.method == 'POST' and form.validate():
            #            username = request.form['username']
            #            useremail = request.form['email']
            countid = int(countid)
            ## cursor ##
            if countid == 1:
                flash('Last consumer user can not be deleted', 'info')
                cur.close()
                return redirect(url_for('manageusers'))
            else:
                #cur2 = conn.cursor()
                cur.execute(" Delete from `UserAccounts` where id = %s", [id])
                cur.execute(" Delete from `TapOwner` where OwnerUID = %s", [id])
                cur.execute(" Delete from `WorkloadOwner` where OwnerUID = %s", [id])
                ## commit and close ##
                conn.commit()
                cur.close()

                flash('Consumer user deleted', 'success')
                return redirect(url_for('manageusers'))
        cur.close()
        return render_template('deleteuser.html', form=form)
    return redirect(url_for('adminlogin'))
    
    
    
    
"""
SETUP SECTION
"""	

@app.route("/psmsetup", methods=['GET', 'POST'])
def psmsetup():
    if 'loggedin' in session and session['admin'] == True:
        form = SetUpPsm(request.form)
        if request.method == 'POST' and form.validate():
            ipman = form.ipman.data
            adminuser = form.adminuser.data
            adminpwd = form.adminpwd.data

            url = 'https://%s/v1/login' % (ipman)
            jsonbody = json.dumps({"username": adminuser, "password": adminpwd, "tenant": "default"}).encode('utf8')
            headers = {'Content-Type': 'application/json'}
            #			print(jsonbody)
            #			print(body)
            #			print(headers)
            req = requests.post(url, headers=headers, data=jsonbody, verify=False)
            #			print(req.status_code)
            if req.status_code == 200:
                #			print(req.headers)
                #			print(req.text)

                info = (req.headers)
                #		info = (((req.json()).get('list-meta')).get('total-count'))
                #		result = req.read()
                #		info = req.info()
                #			print(info)

                cookiePSM = info['set-cookie']
                #			print(cookiePSM)
                x = cookiePSM.index(";")
                cookiekey = cookiePSM[:x]
                #			print(x)
                #			print(cookiekey)
                y = cookiePSM.index("Expires=")

                #			print(y)
                expires = (cookiePSM[y + 8:])
                z = expires.index(";")
                cookieexpiry = expires[:z]
                #			print(cookieexpiry)

                file = open("psm.cfg", "w")
                file.write(
                    f"[global]\nipman = \'{ipman}\'\nadminuser = \'{adminuser}\'\nadminpwd = \'{adminpwd}\'\ncookiekey = \'{cookiekey}\'\nexpiry = \'{cookieexpiry}\'\n")
                file.close()

                return redirect(url_for('adminhome'))
            else:
                msg = "The PSM Registation failed"
                flash(msg, 'warning')

                return render_template('psmsetup.html', msg=msg, form=form)
        return render_template('psmsetup.html', form=form)
    return redirect(url_for('adminlogin'))

@app.route("/targetsetup/", methods=['GET', 'POST'])
def targetsetup():
    """
    The section is for the building the taps to be assigned.
    """
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        result = cur.execute("select uid, name, type, inet_NTOA(IPaddr) as dest  from Taps")
        results = cur.fetchall()

        if result > 0:
            cur.close()
            return render_template('targetsetup.html', results=results)
        else:
            msg = 'No Taps Targets Setup'
            flash(msg, 'warning')
            cur.close()
            return render_template('targetsetup.html', results=results)

        #return render_template('manageusers.html')

    return redirect(url_for('adminlogin'))


@app.route("/workloadsetup/", methods=['GET', 'POST'])
def workloadsetup():
    """
    The section is for the building the taps to be assigned.
    """
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        result = cur.execute("select uid, name ,Description from Workloads")
        results = cur.fetchall()

        if result > 0:
            cur.close()
            return render_template('workloadsetup.html', results=results)
        else:
            msg = 'No Workload Targets Setup'
            flash(msg, 'warning')
            cur.close()
            return render_template('workloadsetup.html', results=results)

        #return render_template('manageusers.html')

    return redirect(url_for('adminlogin'))



@app.route("/deletetaptarget/<string:id>/", methods=['GET', 'POST'])
def deletetaptarget(id):
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        cur.execute(" SELECT uid, name, type, inet_NTOA(IPaddr) as dest FROM `Taps` where UID = %s;", [id])
        results = cur.fetchone()

        form = DeleteTapTargetForm(request.form)
        form.tapname.data = results[1]
        form.taptype.data = results[2]
        form.tapdest.data = results[3]

        #print(results)

        if request.method == 'POST' and form.validate():
            #            username = request.form['username']
            #            useremail = request.form['email']
            cur.execute(" Delete from `Taps` where UID = %s", [id])
            cur.execute(" Delete from `TapOwner` where TapUID = %s", [id])
            ## commit and close ##
            conn.commit()
            cur.close()

            flash('Tap Destination Deleted', 'success')
            return redirect(url_for('targetsetup'))
        cur.close()
        return render_template('deletetaptarget.html', form=form)

    return redirect(url_for('adminlogin'))

@app.route("/deleteworkloadtarget/<string:id>/", methods=['GET', 'POST'])
def deleteworkloadtarget(id):
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        cur.execute("select uid, name ,Description from Workloads where UID = %s;", [id])
        results = cur.fetchone()

        form = DeleteWorkloadTargetForm(request.form)
        form.workloadname.data = results[1]
        form.workloaddesc.data = results[2]

        #print(results)

        if request.method == 'POST' and form.validate():
            cur.execute(" Delete from `Workloads` where UID = %s", [id])
            cur.execute(" Delete from `WorkloadOwner` where WorkloadUID = %s", [id])
            ## commit and close ##
            conn.commit()
            cur.close()

            flash('Workload Destination Deleted', 'success')
            return redirect(url_for('workloadsetup'))
        cur.close()
        return render_template('deleteworkloadtarget.html', form=form)

    return redirect(url_for('adminlogin'))



@app.route("/viewtaptarget/<string:id>/", methods=['GET', 'POST'])
def viewtaptarget(id):
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        result = cur.execute(" SELECT uid, name, type, inet_NTOA(IPaddr) as dest,inet_NTOA(Gateway) as gate , Description, StripVlan, PacketSize   FROM `Taps` where UID = %s;", [id])
        results = cur.fetchone()
        form = ViewTapTargetForm(request.form)

        if request.method == 'GET':
            form.tapname.data = results[1]
            form.taptype.data = results[2]
            form.tapip.data = results[3]
            form.tapgateway.data = results[4]
            form.tapdesc.data = results[5]
            form.tapstrip.data = results[6]
            form.tappacket.data = str(results[7])


        if request.method == 'POST' and form.validate():
            tapname = form.tapname.data
            taptype = form.taptype.data
            tapip = form.tapip.data
            tapgateway = form.tapgateway.data
            tapdesc = form.tapdesc.data
            tapstrip = form.tapstrip.data
            tappacket = form.tappacket.data
            #print(tapname, taptype, tapip,tapgateway,tapdesc,tapstrip,tappacket)

            ## cursor ##
            cur = conn.cursor()
            cur.execute(
                "update `Taps` set Type = %s,"
                "IPaddr = inet_aton(%s),"
                "Gateway = inet_aton(%s),"
                "Description = %s,"
                "StripVlan= %s,"
                "PacketSize = %s "
                "where Name = %s and UID = %s ",
                (taptype, tapip, tapgateway, tapdesc, tapstrip, tappacket , tapname, [id]))

            ## commit and close ##
            conn.commit()
            cur.close()

            flash('Tap Destination Edited', 'success')
            return redirect(url_for('targetsetup'))
        cur.close()
        return render_template('viewtaptarget.html', form=form)
    return redirect(url_for('adminlogin'))

@app.route("/viewworkloadtarget/<string:id>/", methods=['GET', 'POST'])
def viewworkloadtarget(id):
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        cur.execute(" SELECT UID, Name, Description , Source1, Destin1, Prot1, Source2, Destin2, Prot2 FROM `Workloads` where UID = %s;", [id])
        results = cur.fetchone()
        form = ViewWorkloadTargetForm(request.form)

        if request.method == 'GET':
            form.workloadname.data = results[1]
            form.workloaddesc.data = results[2]
            form.worksource1.data = results[3]
            form.workdest1.data = results[4]
            form.workprot1.data = results[5]
            form.worksource2.data = results[6]
            form.workdest2.data = results[7]
            form.workprot2.data = results[8]


        if request.method == 'POST' and form.validate():
            workloadname = form.workloadname.data
            workloaddesc = form.workloaddesc.data
            worksource1 = form.worksource1.data
            workdest1 = form.workdest1.data
            workprot1 = form.workprot1.data
            worksource2 = form.worksource2.data
            workdest2 = form.workdest2.data
            workprot2 = form.workprot2.data


            ## cursor ##
            cur = conn.cursor()
            cur.execute(
                "update `Workloads` set Description = %s,"
                "Source1= %s,"
                "Destin1 = %s, "
                "Prot1 = %s, "
                "Source2= NULLIF(%s,''),"
                "Destin2 = NULLIF(%s,''), "
                "Prot2 = NULLIF(%s,'') "
                "where Name = %s and UID = %s ",
                (workloaddesc, worksource1, workdest1, workprot1, worksource2, workdest2, workprot2,  workloadname, [id]))

            ## commit and close ##
            conn.commit()
            cur.close()

            flash('Workload Destination Edited', 'success')
            return redirect(url_for('workloadsetup'))
        cur.close()
        return render_template('viewworkloadtarget.html', form=form)
    return redirect(url_for('adminlogin'))


@app.route("/addtaptarget", methods=['GET', 'POST'])
def addtaptarget():
    if 'loggedin' in session and session['admin'] == True:
        form = AddTapTargetForm(request.form)
        if request.method == 'POST' and form.validate():
            tapname = form.tapname.data
            taptype = form.taptype.data
            tapip = form.tapip.data
            tapgateway = form.tapgateway.data
            tapdesc = form.tapdesc.data
            tapstrip = form.tapstrip.data
            tappacket = form.tappacket.data

            #print(tapname, taptype, tapip,tapgateway,tapdesc,tapstrip,tappacket)
            ## cursor ##
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO `Taps` (Name, Type, IPaddr, Gateway, Description, StripVlan, PacketSize)"
                "VALUES ( %s,%s,inet_aton(%s),inet_aton(%s),%s,%s,%s ) ",
                (tapname, taptype, tapip,tapgateway,tapdesc,tapstrip,tappacket))

            ## commit and close ##
            conn.commit()
            cur.close()

            flash('Tap Destination Created', 'success')
            return redirect(url_for('targetsetup'))


        return render_template('addtaptarget.html', form=form)
    return redirect(url_for('adminlogin'))

@app.route("/addworkloadtarget", methods=['GET', 'POST'])
def addworkloadtarget():
    if 'loggedin' in session and session['admin'] == True:
        form = AddWorkloadTargetForm(request.form)
        if request.method == 'POST' and form.validate():
            workloadname = form.workloadname.data
            workloaddesc = form.workloaddesc.data
            worksource1 = form.worksource1.data
            workdest1 = form.workdest1.data
            workprot1 = form.workprot1.data
            worksource2 = form.worksource2.data
            workdest2 = form.workdest2.data
            workprot2 = form.workprot2.data

            #print((workloadname, worksource1, worksource2,workdest1,workdest2,workprot1,workprot2,workloaddesc))
            ## cursor ##
            cur = conn.cursor()
            cur.execute(
                " INSERT INTO `Workloads` (Name, Source1, Source2, Destin1, Destin2, Prot1, Prot2, Description)"
                "VALUES ( %s,%s,%s,%s,NULLIF(%s,''),NULLIF(%s,''),NULLIF(%s,''),%s ) ",
                (workloadname, worksource1, worksource2,workdest1,workdest2,workprot1,workprot2,workloaddesc))

            ## commit and close ##
            conn.commit()
            cur.close()

            flash('Tap Destination Created', 'success')
            return redirect(url_for('workloadsetup'))


        return render_template('addworkloadtarget.html', form=form)
    return redirect(url_for('adminlogin'))


@app.route("/assigntaps/<string:id>/", methods=['GET', 'POST'])
def assigntaps(id):
    """
    The section is for the assigning of taps to a specific user. 
    Select 1 retrieves the TAPS not already assigned to the user.
    Select 2 retrieves the username of the user the tap is being assigned too for display purpose
    """
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        userid = [id]
        result = cur.execute("select uid, name, type, inet_NTOA(IPaddr) as dest  from Taps where UID in (select TapUID from TapOwner where OwnerUID=%s)",  [id])
        results = cur.fetchall()
        cur.execute("select username from UserAccounts where id=%s", [id])
        results2 = cur.fetchone()

        if result > 0:
            cur.close()
            return render_template('assigntaps.html', results=results, userid=userid, results2=results2)
        else:
            flash ('No Taps Assigned', 'error')
            cur.close()
            return render_template('assigntaps.html', results=results, userid=userid, results2=results2)

        #return render_template('manageusers.html')

    return redirect(url_for('adminlogin'))


@app.route("/addassignedtap/", methods=['GET', 'POST'])
def addassignedtap():
    # TODO: This is where i am upto. 
    # TODO: need to look at the format and work out the register process. - http://192.168.102.6:5010/addmember/?GUID=1&DHCPUID=409
    userid = request.args.get('userid', None)
    #print(userid)
    if 'loggedin' in session and session['admin'] == True:
        ## cursor ##
        cur = conn.cursor()
        result = cur.execute(" select uid, Name, Type, INET_NTOA(IPaddr) from Taps where UID not in (select tapuid from TapOwner where OwnerUID=%s);", userid)
        results = cur.fetchall()
        cur.execute("select id, username from UserAccounts where id=%s", userid)
        results2 = cur.fetchone()
        if result > 0:
            cur.close()
            return render_template('addassignedtap.html', results=results, userid=userid , results2=results2)
        else:
            flash( 'No Taps Left', 'success')
            cur.close()
            return render_template('addassignedtap.html', results=results, userid=userid , results2=results2)


    return redirect(url_for('adminlogin'))


@app.route("/addassignedworkload/", methods=['GET', 'POST'])
def addassignedworkload():
    # TODO: This is where i am upto.
    # TODO: need to look at the format and work out the register process. - http://192.168.102.6:5010/addmember/?GUID=1&DHCPUID=409
    userid = request.args.get('userid', None)
    #print(userid)
    if 'loggedin' in session and session['admin'] == True:
        ## cursor ##
        cur = conn.cursor()
        result = cur.execute(
            " select uid, Name from Workloads where "
            "UID not in (select WorkloadUID from WorkloadOwner where OwnerUID=%s);", userid)
        results = cur.fetchall()
        cur.execute("select id, username from UserAccounts where id=%s", userid)
        results2 = cur.fetchone()
        if result > 0:
            cur.close()
            return render_template('addassignedworkload.html', results=results, userid=userid , results2=results2)
        else:
            flash('No workloads Left', 'success')
            cur.close()
            return render_template('addassignedworkload.html', results=results, userid=userid , results2=results2)

    return redirect(url_for('adminlogin'))



@app.route("/addassignedtapcreate/", methods=['GET', 'POST'])
def addassignedtapcreate():
    userid = request.args.get('userid', None)
    tapid = request.args.get('Tapid', None)

    if 'loggedin' in session and session['admin'] == True:
        flash('Tap Assigned', 'success')
        cur = conn.cursor()
        state = ("insert into TapOwner (TapUID, OwnerUID) values(%s,%s);" %  (tapid,userid))
        cur.execute(state)
        cur.close()
        conn.commit()
        return redirect(url_for('addassignedtap',userid=userid))


@app.route("/addassignedworkloadcreate/", methods=['GET', 'POST'])
def addassignedworkloadcreate():
    userid = request.args.get('userid', None)
    workloadid = request.args.get('workloadid', None)

    if 'loggedin' in session and session['admin'] == True:
        flash('Workload Assigned', 'success')
        cur = conn.cursor()
        state = (
                     "insert into WorkloadOwner (WorkloadUID, OwnerUID) values(%s,%s);" %  (workloadid,userid))
        cur.execute(state)
        cur.close()
        conn.commit()
        return redirect(url_for('addassignedworkload',userid=userid))



@app.route("/deleteasignedtap/", methods=['GET', 'POST'])
def deleteasignedtap():
    tapid = request.args.get('Tapid', None)
    userid = request.args.get('userid', None)
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        cur.execute("select uid, name, type, inet_NTOA(IPaddr) as dest  from Taps where UID=%s;", tapid)
        results = cur.fetchone()
        form = DeleteAssignedTapForm(request.form)
        form.tapname.data = results[1]
        form.destination.data = results[3]

        if request.method == 'POST' and form.validate():
            cur.execute("delete from TapOwner where TapUID = %s and OwnerUID =%s;", (tapid, userid))
            conn.commit()
            cur.close()
            flash('Taps removed', 'success')
            return redirect(url_for('manageusers'))
        cur.close()
        return render_template('deleteasignedtap.html', form=form)

    return redirect(url_for('adminlogin'))


@app.route("/deleteasignedworkload/", methods=['GET', 'POST'])
def deleteasignedworkload():
    workloadid = request.args.get('workloadid', None)
    userid = request.args.get('userid', None)
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        cur.execute("select uid, name as dest  from Workloads where UID=%s;", workloadid)
        results = cur.fetchone()
        form = DeleteAssignedWorkloadForm(request.form)
        form.workloadname.data = results[1]

        if request.method == 'POST' and form.validate():
            cur.execute("delete from WorkloadOwner where WorkloadUID = %s and OwnerUID =%s;", (workloadid, userid))
            conn.commit()
            cur.close()
            flash('Workload removed', 'success')
            return redirect(url_for('manageusers'))
        cur.close()
        return render_template('deleteasignedworkload.html', form=form)

    return redirect(url_for('adminlogin'))


@app.route("/assignworkload/<string:id>/", methods=['GET', 'POST'])
def assignworkload(id):
    if 'loggedin' in session and session['admin'] == True:
        cur = conn.cursor()
        userid = [id]
        result = cur.execute("select uid, name as workload from Workloads where UID in (select WorkloadUID from WorkloadOwner where OwnerUID=%s)",  [id])
        results = cur.fetchall()
        cur.execute("select username from UserAccounts where id=%s", [id])
        results2 = cur.fetchone()

        if result > 0:
            cur.close()
            return render_template('assignworkload.html', results=results, userid=userid, results2=results2)
        else:
            flash ( 'No Workloads Assigned', 'error')
            cur.close()
            return render_template('assignworkload.html', results=results, userid=userid, results2=results2)

    return redirect(url_for('adminlogin'))

    


"""
ADMIN TAPS AND ACTIVE TAPS SECTION
"""

@app.route("/adminactivetap")
def adminactivetap():
    if 'loggedin' in session and session['admin'] == True:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            return redirect(url_for('psmsetup'))

        url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession' % (ipman))
        headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})
        try:
            req = requests.get(url, headers=headers, verify=False)
        except requests.ConnectionError:
            msg = 'No PSM accessible'
            flash(msg, 'warning')
            return redirect(url_for('adminhome'))
        # handle ConnectionError the exception

        ''' print the number of taps'''
        flash(f"The number of taps configure on PSM = {(((req.json()).get('list-meta')).get('total-count'))}\n", 'info')

        cur = conn.cursor()
        result = cur.execute("select uid, TapName , TapExpiry , TapId from ActiveTaps;")
        results = cur.fetchall()
        if result > 0:
            cur.close()
            return render_template('adminactivetap.html', results=results)
        else:
            msg = 'No Active Taps registered'
            flash(msg, 'warning')
            cur.close()
            return render_template('adminactivetap.html', msg=msg)

    return redirect(url_for('adminlogin'))

@app.route("/adminenabletap")
def adminenabletap():
    if 'loggedin' in session and session['admin'] == True:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            return redirect(url_for('psmsetup'))

        url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession' % (ipman))
        headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})
        try:
            req = requests.get(url, headers=headers, verify=False)
        except requests.ConnectionError:
            msg = 'No PSM accessable'
            flash(msg, 'warning')
            return redirect(url_for('adminhome'))

        tapcount = (((req.json()).get('list-meta')).get('total-count'))
        if tapcount is None:
            tapcount = 0

        '''if tap count greater than or equal 8 exit'''
        if tapcount >= 8:
            flash('Max Taps configured on PSM', 'success')
            return redirect(url_for('adminactivetap'))

        ''' Import the content for the drop downs'''
        cur = conn.cursor()
        result = cur.execute("select uid, name as tap from Taps;")
        results = cur.fetchall()
        cur2 = conn.cursor()
        result2 = cur.execute("select uid, name as workload from Workloads;")
        results2 = cur.fetchall()
        if result > 0 and result2 > 0:
            cur.close()
            return render_template('adminenabletap.html', results=results, results2=results2)
        else:
            msg = 'Either no Taps or Workloads Configured'
            flash(msg, 'warning')
            cur.close()
            return redirect(url_for('adminhome'))

    return redirect(url_for('adminlogin'))


@app.route("/adminenabletapcreate/", methods=['GET', 'POST'])
def adminenabletapcreate():
    TapDest = request.args.get('TapDest', None)
    WorkDest = request.args.get('WorkDest', None)
    Duration = (int)(request.args.get('Duration', None))
    if 'loggedin' in session and session['admin'] == True:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            return redirect(url_for('psmsetup'))

        ## cursor ##
        cur1 = conn.cursor()
        cur1.execute(
            " select Name, Type, INET_NTOA(IPaddr), INET_NTOA(Gateway), StripVlan, PacketSize from "
            "Taps where UID =%s;",
            TapDest)
        resultstap = cur1.fetchone()
        TapName= resultstap[0]
        TapType = resultstap[1]
        TapDest = resultstap[2]
        TapGateway = resultstap[3]
        TapStrip = resultstap[4]
        TapPacket = resultstap[5]
        cur1.close()

        cur2 = conn.cursor()
        cur2.execute(
            " select Name, Source1,Destin1,Prot1, Source2,Destin2,Prot2 from Workloads where uid=%s;",
                     WorkDest)
        resultswork = cur2.fetchone()
        WorkName = resultswork[0]
        WorkSoure1 = resultswork[1]
        WorkDest1 = resultswork[2]
        WorkPro1 = resultswork[3]
        WorkSoure2 = resultswork[4]
        WorkDest2 = resultswork[5]
        WorkPro2 = resultswork[6]
        cur2.close()

        MirrorName = (TapName +'-'+ WorkName)

        cur3 = conn.cursor()
        state3 = (
                "insert into ActiveTaps (TapName, TapExpiry)"
                "Values ('%s',(date_add(now(),INTERVAL %s minute)));") % (
                     MirrorName, Duration)
        cur3.execute(state3)
        conn.commit()
        cur3.close()
        cur4 = conn.cursor()
        state4=("select uid , TapExpiry from ActiveTaps where TapName='%s';") % (MirrorName)
        cur4.execute(state4)
        results4 = cur4.fetchone()
        TapId=int(results4[0])
        cur4.close()

        url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession' % ipman)
        headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})

        # TODO: Need to work on the build array logic.
        #print(TapStrip)
        header = ("""
                            "meta":{"name":"%s"}
                            """ % (MirrorName))

        if TapStrip == 'Yes':
            collector = ("""
                        "spec":{"packet-size":%s, 
                        "collectors":[
                            {"type":"%s",
                            "export-config":{
                                "destination":"%s",
                                "gateway":"%s"
                                },
                            "strip-vlan-hdr": true}
                            ]
                        """ % (TapPacket, TapType, TapDest, TapGateway))
        else:
            collector = ("""
                        "spec":{"packet-size":%s, 
                        "collectors":[
                            {"type":"%s",
                            "export-config":{
                                "destination":"%s",
                                "gateway":"%s"
                                }
                            }
                            ]
                        """ % (TapPacket, TapType, TapDest, TapGateway))
        if WorkSoure2 is None:
            print("single")
            rules = ("""
                        "match-rules":[{
                            "source":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "destination":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "app-protocol-selectors":{
                                "proto-ports":[
                                    "%s"
                                ]
                            }
                        }]
                        """ %(WorkSoure1,WorkDest1,WorkPro1))
        else:
            print("double")
            rules = ("""
                        "match-rules":[{
                            "source":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "destination":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "app-protocol-selectors":{
                                "proto-ports":[
                                    "%s"
                                ]
                            }
                        },
                            {
                            "source":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "destination":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "app-protocol-selectors":{
                                "proto-ports":[
                                    "%s"
                                ]
                            }
                        }
                        ]
                        """ % (WorkSoure1,WorkDest1,WorkPro1,WorkSoure2,WorkDest2,WorkPro2 ))

        spanid = ("""
            		"packet-filters": [
                        "all-packets"
                    ],
                    "span-id": %s
                    }
                """ % (TapId))
        body = ("""{%s,%s,%s,%s}
                    """ % (header,collector,rules,spanid))
        #print(body)

        req = requests.post(url, headers=headers, data=body, verify=False)
        """"
        print(req.status_code)
        print(req.headers)
        print(req.text)
        """
        if req.status_code == 200:
            cur5 = conn.cursor()
            state5 = (
                         "update ActiveTaps set TapId = %s ,"
                        "TapExpiry = (date_add(now(),INTERVAL %s minute))"
                        "where TapName ='%s';") % (TapId,Duration, MirrorName)
            cur5.execute(state5)
            conn.commit()
            cur5.close()

        elif req.status_code != 200:
            flash('Tap failed to be added', 'error')
            cur5 = conn.cursor()
            state5 = ("delete from ActiveTaps  where TapName = '%s' and TapId is null;" ) % (MirrorName)
            cur5.execute(state5)
            conn.commit()
            cur5.close()
            return redirect(url_for('adminactivetap'))

        return redirect(url_for('adminactivetap'))

    return redirect(url_for('adminlogin'))


@app.route("/admindeletetap/<string:id>/", methods=['GET', 'POST'])
def admindeletetap(id):
    if 'loggedin' in session and session['admin'] == True:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            print('empty String')
            return redirect(url_for('psmsetup'))

        cur = conn.cursor()
        result = cur.execute(" select uid, TapName , TapExpiry from ActiveTaps where uid = %s;", [id])
        results = cur.fetchone()
        cur.close()
        if result > 0:
            form = DeleteTapForm(request.form)
            form.tapname.data = results[1]
            form.tapexpiry.data = results[2]
            tapname = results[1]
        else:
            flash('Tap already deleted', 'success')
            return redirect(url_for('adminactivetap'))

        if request.method == 'POST' and form.validate():
            cur = conn.cursor()
            result = cur.execute(" select uid, TapName , TapExpiry from ActiveTaps where uid = %s;", [id])
            cur.close()
            if result > 0:
                url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession/%s' % (ipman, tapname))
                headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})
                # body = """{"meta":{"name":"ExampleMirror"},"spec":{"packet-size":2048,"collectors":[{"type":"erspan_type_3","export-config":{"destination":"192.168.102.106","gateway":"192.168.102.1"},"strip-vlan-hdr":null}],"match-rules":[{"source":{"ip-addresses":["192.168.101.0/24"]},"destination":{"ip-addresses":["any"]},"app-protocol-selectors":{"proto-ports":["any"]}},{"source":{"ip-addresses":["any"]},"destination":{"ip-addresses":["192.168.101.0/24"]},"app-protocol-selectors":{"proto-ports":["any"]}}],"packet-filters":["all-packets"],"interfaces":null,"span-id":2}}"""
                req = requests.delete(url, headers=headers, verify=False)
                # print(req.status_code)
                # print(req.headers)
                # print(req.text)

                if req.status_code == 200:
                    cur2 = conn.cursor()
                    cur2.execute(" Delete from `ActiveTaps` where uid = %s", [id])
                    ## commit and close ##
                    conn.commit()
                    cur2.close()
                    flash('Tap deleted', 'success')
                    return redirect(url_for('adminactivetap'))
                return redirect(url_for('adminactivetap'))
            else:
                flash('Tap already deleted', 'success')
                return redirect(url_for('adminactivetap'))

        return render_template('admindeletetap.html', form=form)
    return redirect(url_for('adminlogin'))



"""
USERS TAPS AND ACTIVE TAPS SECTION
"""

@app.route("/activetap")
def activetap():
    if 'loggedin' in session:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            print('empty String')
            return redirect(url_for('psmsetup'))
        url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession' % (ipman))
        headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})
        try:
            req = requests.get(url, headers=headers, verify=False)
        except requests.ConnectionError:
            msg = 'No PSM accessable'
            flash(msg, 'warning')
            return redirect(url_for('home'))


        ''' print the number of taps'''
        flash(f"The number of taps configure on PSM = {(((req.json()).get('list-meta')).get('total-count'))}\n", 'info')

        '''
        # Display in console the names of all the TAP configured on PSM.
        data5 = ((req.json()).get('items'))
        for item in data5:
            tapname=((item.get('meta')).get('name'))
            # print("MetaData: {}\n".format(item['meta']))
            print(f"Tapname: {tapname}\n")
        '''
        #print(session['id'])
        cur = conn.cursor()
        result = cur.execute("select uid, TapName , TapExpiry  , TapId  from ActiveTaps where TapOwner = %s;", [session['id']])
        results = cur.fetchall()
        if result > 0:
            cur.close()
            return render_template('activetap.html', results=results)
        else:
            msg = 'No Active Taps registered'
            flash(msg, 'warning')
            cur.close()
            return render_template('activetap.html', msg=msg)


    return redirect(url_for('home'))


@app.route("/enabletap")
def enabletap():
    if 'loggedin' in session:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            print('empty String')
            return redirect(url_for('psmsetup'))

        url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession' % (ipman))
        headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})

        try:
            req = requests.get(url, headers=headers, verify=False)
        except requests.ConnectionError:
            msg = 'No PSM accessable'
            flash(msg, 'warning')
            return redirect(url_for('home'))

        tapcount = (((req.json()).get('list-meta')).get('total-count'))
        if tapcount is None:
            tapcount=0

        '''
        print(req.status_code)
        print(req.headers)
        print(req.text)        
        print(f"number of taps ={(((req.json()).get('list-meta')).get('total-count'))}\n")
             
        print(tapcount)
        data = req.json()
        print(data)
        data2 = (data.get('list-meta'))
        print(data2)
        data3 = (data2.get('total-count'))
        print(data3)
        print(f"number of taps configure on PSM ={(((req.json()).get('list-meta')).get('total-count'))}\n")
        '''
        '''if tap count greater than or equal 8 exit'''
        if tapcount >= 8:
            flash('Max Taps configured on PSM', 'success')
            return redirect(url_for('activetap'))

        ''' Import the content for the drop downs'''
        cur = conn.cursor()
        result = cur.execute("select uid, name as tap from Taps where UID in (select TapUID from TapOwner where OwnerUID=%s)", [session['id']])
        results = cur.fetchall()
        result2 = cur.execute("select uid, name as workload from Workloads where UID in (select WorkloadUID from WorkloadOwner where OwnerUID=%s)", [session['id']])
        results2 = cur.fetchall()
        if result > 0 and result2 > 0:
            cur.close()
            return render_template('enabletap.html', results=results, results2=results2)
        else:
            msg = 'Either no Taps or Workloads Configured'
            flash(msg, 'warning')
            cur.close()
            return redirect(url_for('home'))


    return redirect(url_for('home'))



@app.route("/enabletapcreate/", methods=['GET', 'POST'])
def enabletapcreate():
    TapDest = request.args.get('TapDest', None)
    WorkDest = request.args.get('WorkDest', None)
    Duration = request.args.get('Duration', None)
    Tapowner = session['id']
    #print(TapDest)
    #print(WorkDest)
    #print(Duration)
    if 'loggedin' in session:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            return redirect(url_for('psmsetup'))

        ## cursor ##
        cur1 = conn.cursor()
        cur1.execute(
            " select Name, Type, INET_NTOA(IPaddr), INET_NTOA(Gateway), StripVlan, PacketSize from "
            "Taps where UID =%s;",
            TapDest)
        resultstap = cur1.fetchone()
        TapName= resultstap[0]
        TapType = resultstap[1]
        TapDest = resultstap[2]
        TapGateway = resultstap[3]
        TapStrip = resultstap[4]
        TapPacket = resultstap[5]
        cur1.close()

        cur2 = conn.cursor()
        cur2.execute(
            " select Name, Source1,Destin1,Prot1, Source2,Destin2,Prot2 from Workloads where uid=%s;",
                     WorkDest)
        resultswork = cur2.fetchone()
        WorkName = resultswork[0]
        WorkSoure1 = resultswork[1]
        WorkDest1 = resultswork[2]
        WorkPro1 = resultswork[3]
        WorkSoure2 = resultswork[4]
        WorkDest2 = resultswork[5]
        WorkPro2 = resultswork[6]
        cur2.close()

        MirrorName = (TapName +'-'+ WorkName)

        cur3 = conn.cursor()
        state3 = (
                "insert into ActiveTaps (TapName, TapExpiry, TapOwner)"
                "Values ('%s',(date_add(now(),INTERVAL %s minute)), %s);") % (
                     MirrorName, Duration, Tapowner)
        cur3.execute(state3)
        conn.commit()
        cur3.close()
        cur4 = conn.cursor()
        state4=("select uid , TapExpiry from ActiveTaps where TapName='%s';") % (MirrorName)
        cur4.execute(state4)
        results4 = cur4.fetchone()
        TapId=int(results4[0])
        cur4.close()

        url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession' % ipman)
        headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})

        # TODO: Need to work on the build array logic.
        #print(TapStrip)
        header = ("""
                            "meta":{"name":"%s"}
                            """ % (MirrorName))

        if TapStrip == 'Yes':
            collector = ("""
                        "spec":{"packet-size":%s, 
                        "collectors":[
                            {"type":"%s",
                            "export-config":{
                                "destination":"%s",
                                "gateway":"%s"
                                },
                            "strip-vlan-hdr": true}
                            ]
                        """ % (TapPacket, TapType, TapDest, TapGateway))
        else:
            collector = ("""
                        "spec":{"packet-size":%s, 
                        "collectors":[
                            {"type":"%s",
                            "export-config":{
                                "destination":"%s",
                                "gateway":"%s"
                                }
                            }
                            ]
                        """ % (TapPacket, TapType, TapDest, TapGateway))
        if WorkSoure2 is None:
            #print("single")
            rules = ("""
                        "match-rules":[{
                            "source":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "destination":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "app-protocol-selectors":{
                                "proto-ports":[
                                    "%s"
                                ]
                            }
                        }]
                        """ %(WorkSoure1,WorkDest1,WorkPro1))
        else:
            #print("double")
            rules = ("""
                        "match-rules":[{
                            "source":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "destination":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "app-protocol-selectors":{
                                "proto-ports":[
                                    "%s"
                                ]
                            }
                        },
                            {
                            "source":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "destination":{
                                "ip-addresses":[
                                    "%s"
                                ]
                            },
                            "app-protocol-selectors":{
                                "proto-ports":[
                                    "%s"
                                ]
                            }
                        }
                        ]
                        """ % (WorkSoure1,WorkDest1,WorkPro1,WorkSoure2,WorkDest2,WorkPro2 ))

        spanid = ("""
            		"packet-filters": [
                        "all-packets"
                    ],
                    "span-id": %s
                    }
                """ % (TapId))
        body = ("""{%s,%s,%s,%s}
                    """ % (header,collector,rules,spanid))
        #print(body)

        req = requests.post(url, headers=headers, data=body, verify=False)
        """"
        print(req.status_code)
        print(req.headers)
        print(req.text)
        """
        if req.status_code == 200:
            cur5 = conn.cursor()
            state5 = (
                         "update ActiveTaps set TapId = %s ,"
                         "TapExpiry = (date_add(now(),INTERVAL %s minute))"
                        "where TapName ='%s';") % (TapId,Duration, MirrorName)
            cur5.execute(state5)
            conn.commit()
            cur5.close()

        elif req.status_code != 200:
            flash('Tap failed to be added', 'error')
            cur5 = conn.cursor()
            state5 = ("delete from ActiveTaps  where TapName = '%s' and TapId is null;" ) % (MirrorName)
            cur5.execute(state5)
            conn.commit()
            cur5.close()
            return redirect(url_for('activetap'))

        return redirect(url_for('activetap'))

    return redirect(url_for('home'))




@app.route("/deletetap/<string:id>/", methods=['GET', 'POST'])
def deletetap(id):
    if 'loggedin' in session:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            #print('empty String')
            return redirect(url_for('psmsetup'))

        cur = conn.cursor()
        result = cur.execute(" select uid, TapName , TapExpiry from ActiveTaps where uid = %s;", [id])
        results = cur.fetchone()
        cur.close()
        if result > 0:
            form = DeleteTapForm(request.form)
            form.tapname.data = results[1]
            form.tapexpiry.data = results[2]
            tapname = results[1]
        else:
            flash('Tap already deleted', 'success')
            return redirect(url_for('activetap'))


        if request.method == 'POST' and form.validate():
            cur = conn.cursor()
            result = cur.execute(" select uid, TapName , TapExpiry from ActiveTaps where uid = %s;", [id])
            cur.close()
            if result > 0:
                url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession/%s' % (ipman, tapname))
                headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})
                # body = """{"meta":{"name":"ExampleMirror"},"spec":{"packet-size":2048,"collectors":[{"type":"erspan_type_3","export-config":{"destination":"192.168.102.106","gateway":"192.168.102.1"},"strip-vlan-hdr":null}],"match-rules":[{"source":{"ip-addresses":["192.168.101.0/24"]},"destination":{"ip-addresses":["any"]},"app-protocol-selectors":{"proto-ports":["any"]}},{"source":{"ip-addresses":["any"]},"destination":{"ip-addresses":["192.168.101.0/24"]},"app-protocol-selectors":{"proto-ports":["any"]}}],"packet-filters":["all-packets"],"interfaces":null,"span-id":2}}"""
                req = requests.delete(url, headers=headers, verify=False)
                # print(req.status_code)
                # print(req.headers)
                # print(req.text)

                if req.status_code == 200:
                    cur2 = conn.cursor()
                    cur2.execute(" Delete from `ActiveTaps` where uid = %s", [id])
                    ## commit and close ##
                    conn.commit()
                    cur2.close()
                    flash('Tap deleted', 'success')
                    return redirect(url_for('activetap'))
                return redirect(url_for('activetap'))
            else:
                flash('Tap already deleted', 'success')
                return redirect(url_for('activetap'))

        return render_template('deletetap.html', form=form)
    return redirect(url_for('home'))


"""
HOME PAGE 
    Check if user is loggedin is admin or user.
    Then checks to see if the PSM SETUP is completed.
    If no PSM Setup it will redirect to the PSM setup, if a user this will cause redirect to login.
"""

@app.route("/")
def index():
    # Check if user is loggedin
    if 'loggedin' in session and session['admin'] == True:
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            #print('empty String')
            return redirect(url_for('psmsetup'))

        return render_template('adminindex.html')
    elif 'loggedin' in session and session['admin'] == False:
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            #print('empty String')
            return redirect(url_for('psmsetup'))

        return render_template('index.html')

    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route("/home")
def home():
    # Check if user is loggedin
    if 'loggedin' in session and session['admin'] == True:
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            #print('empty String')
            return redirect(url_for('psmsetup'))

        return render_template('adminindex.html')
    elif 'loggedin' in session and session['admin'] == False:
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            #print('empty String')
            return redirect(url_for('psmsetup'))

        return render_template('index.html')

    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route("/adminhome")
def adminhome():
    # Check if user is loggedin
    if 'loggedin' in session and session['admin'] == True:
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            #print('empty String')
            return redirect(url_for('psmsetup'))

        return render_template('adminindex.html')
    elif 'loggedin' in session and session['admin'] == False:
        cookiekey = getVar('cookiekey')[1:-1]
        if len(cookiekey) == 0:
            #print('empty String')
            return redirect(url_for('psmsetup'))

        return render_template('index.html')

    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

"""
BACKGROUND SECTION 

"""	

def getVar(name):
    ' Global variable retrival from psm.cfg'
    c = ConfigParser()
    c.read('psm.cfg')
    return c.get('global',name)


def initBackgroundProcs():
    ''' Intial process for threading and background jobs. '''
    thread1 = threading.Thread(target=refreshkey)
    thread2 = threading.Thread(target=expiryactivetaps)
    thread1.start()
    thread2.start()

def refreshkey():
    ''' 	Background job to refresh the API token every few days. '''
    while True :
        expiry = getVar('expiry')[1:-1]
        today = datetime.today()
        expirytest = (datetime.strptime(expiry, '%a, %d  %b %Y %H:%M:%S %Z')) + timedelta(days=-1)

        if (today > expirytest):
            ipman = getVar('ipman')[1:-1]
            adminuser = getVar('adminuser')[1:-1]
            adminpwd = getVar('adminpwd')[1:-1]

            url = 'https://%s/v1/login' % (ipman)
            jsonbody = json.dumps({"username": adminuser, "password": adminpwd, "tenant": "default"}).encode('utf8')
            headers = {'Content-Type': 'application/json'}
            #			print(jsonbody)
            #			print(body)
            #			print(headers)
            req = requests.post(url, headers=headers, data=jsonbody, verify=False)
            #			print(req.status_code)
            if req.status_code == 200:
                #			print(req.headers)
                #			print(req.text)

                info = (req.headers)
                #		info = (((req.json()).get('list-meta')).get('total-count'))
                #		result = req.read()
                #		info = req.info()
                #			print(info)

                cookiePSM = info['set-cookie']
                #			print(cookiePSM)
                x = cookiePSM.index(";")
                cookiekey = cookiePSM[:x]
                #			print(x)
                #			print(cookiekey)
                y = cookiePSM.index("Expires=")

                #			print(y)
                expires = (cookiePSM[y + 8:])
                z = expires.index(";")
                cookieexpiry = expires[:z]
                #			print(cookieexpiry)

                file = open("psm.cfg", "w")
                file.write(
                    f"[global]\nipman = \'{ipman}\'\nadminuser = \'{adminuser}\'\nadminpwd = \'{adminpwd}\'\ncookiekey = \'{cookiekey}\'\nexpiry = \'{cookieexpiry}\'\n")
                file.close()
                
                print("Key Updated")

            else:
                '''Sleep for 12 hours before re-test'''
                time.sleep(43200)

        else:
            time.sleep(43200)


def expiryactivetaps():
    ''' 	Background job to delete the active taps that have expired. '''
    while True:
        ipman = getVar('ipman')[1:-1]
        cookiekey = getVar('cookiekey')[1:-1]

        if len(cookiekey) != 0:
            cur = conn.cursor()
            result = cur.execute(" select uid, TapName , TapExpiry from ActiveTaps where TapExpiry < now();")
            results = cur.fetchall()
            if result > 0:
                for row in results:
                    tapname = row[1]
                    tapid = row[0]
                    url = ('https://%s/configs/monitoring/v1/tenant/default/MirrorSession/%s' % (ipman, tapname))
                    headers = ({'Content-Type': 'application/json', 'cookie': cookiekey})
                    # body = """{"meta":{"name":"ExampleMirror"},"spec":{"packet-size":2048,"collectors":[{"type":"erspan_type_3","export-config":{"destination":"192.168.102.106","gateway":"192.168.102.1"},"strip-vlan-hdr":null}],"match-rules":[{"source":{"ip-addresses":["192.168.101.0/24"]},"destination":{"ip-addresses":["any"]},"app-protocol-selectors":{"proto-ports":["any"]}},{"source":{"ip-addresses":["any"]},"destination":{"ip-addresses":["192.168.101.0/24"]},"app-protocol-selectors":{"proto-ports":["any"]}}],"packet-filters":["all-packets"],"interfaces":null,"span-id":2}}"""
                    req = requests.delete(url, headers=headers, verify=False)
                    #print(req.status_code)
                    #print(req.headers)
                    #print(req.text)

                    if req.status_code == 200:
                        cur.execute(" Delete from `ActiveTaps` where uid = %s", tapid)
                        ## commit and close ##
                        conn.commit()
                    #else:

                cur.close()
                time.sleep(60)
            else:
                cur.close()
                time.sleep(60)

        else:
            time.sleep(300)

"""
FORM DATA SECTION FOR VALIDATION.
"""	
    

class ChangePwd(Form):
    currentpwd = PasswordField('Current Password', [validators.Length(min=1, max=50)])
    newpwd = PasswordField('New Password',
                           [validators.DataRequired(), validators.EqualTo('checkpwd', message='Passwords must match')])
    checkpwd = PasswordField('Repeat New Password')


class AddAdminForm(Form):
    username = StringField('Login', [validators.Length(min=1, max=50)])
    useremail = EmailField('Email address', [validators.DataRequired(), validators.Email()])
    userpassword = PasswordField('New Password', [validators.DataRequired(),
                                                  validators.EqualTo('checkpwd', message='Passwords must match')])
    checkpwd = PasswordField('Repeat New Password')


class AddTapTargetForm(Form):
    erspan = [ ('erspan_type_3', 'ERSPAN Type 3'),('erspan_type_2', 'ERSPAN Type 2')]
    packet = [('2048', 'Full'),  ('1024', '1024'),  ('512', '512'),('256', '256'),('128', '128'),  ('64', '64')]
    #packet = [(2048, 2048), (1024, 1024), (512, 512), (256, 256), (128, 128), (64, 64)]
    tapvlan =  [('Y', 'Yes'), ('N', 'No')]
    tapname = StringField('Tap service Name', [validators.Length(min=1, max=50, message="Name is required as will be used in the any Tap rules")])
    taptype = SelectField('ERSPAN Type', choices = erspan )
    tapip =  StringField('Destination IP', [validators.IPAddress(ipv4=True , message="Enter a valid IP Address")])
    tapgateway = StringField('Gateway', [validators.IPAddress(ipv4=True , message="Enter a valid IP Address")])
    tapdesc = StringField('Description', [validators.Length(min=1, max=50, message="Please enter a description/reason" )])
    tapstrip = SelectField('Strip Vlan', choices = tapvlan)
    tappacket = SelectField('Packet Size', choices = packet)

class ViewTapTargetForm(Form):
    erspan = [ ('erspan_type_3', 'ERSPAN Type 3'),('erspan_type_2', 'ERSPAN Type 2')]
    tapvlan = [('Yes', 'Yes'), ('No', 'No')]
    packet = [('2048', 'Full'),  ('1024', '1024'),  ('512', '512'),('256', '256'),('128', '128'),  ('64', '64')]
    tapname = StringField('Tap service Name', render_kw={'readonly': True})
    taptype = SelectField('ERSPAN Type', choices = erspan )
    tapip =  StringField('Destination IP', render_kw={'readonly': True})
    tapgateway = StringField('Gateway', render_kw={'readonly': True})
    tapdesc = StringField('Description', [validators.Length(min=1, max=50, message="Please enter a description/reason" )])
    tapstrip = SelectField('Strip Vlan', choices = tapvlan)
    tappacket = SelectField('Packet Size', choices = packet)



class AddWorkloadTargetForm(Form):
    workloadname = StringField('Workload Filter Name', [validators.Length(min=1, max=50, message="Name is required as will be used in the any Tap rules")])
    workloaddesc = StringField('Filter Description', [validators.Length(min=1, max=50, message="Local Description")])
    worksource1 = StringField('Filter Source 1 - Option of format are (a.b.c.d/e or a.b.c.d or any)', [validators.Length(min=1, max=100, message="Format -------" )])
    workdest1 = StringField('Filter Destination 1 - Option of format are (a.b.c.d/e or a.b.c.d or any)', [validators.Length(min=1, max=100, message="Format -------")])
    workprot1 = StringField('Filter Protocol 1 - Option of format are (icmp or any or tcp/5000-5100)', [validators.Length(min=1, max=100, message="Format -------")])
    worksource2 = StringField('Filter Source 2 - Option of format are (a.b.c.d/e or a.b.c.d or any)', [validators.Length(min=0, max=100, message="Format -------")])
    workdest2 = StringField('Filter Destination 2 - Option of format are (a.b.c.d/e or a.b.c.d or any)', [validators.Length(min=0, max=100, message="Format -------")])
    workprot2 = StringField('Filter Protocol 2 - Option of format are (22 or 22,23,24 or any)', [validators.Length(min=0, max=100, message="Format -------")])

class ViewWorkloadTargetForm(Form):
    workloadname = StringField('Workload Filter Name', render_kw={'readonly': True})
    workloaddesc = StringField('Filter Description', [validators.Length(min=1, max=50, message="Local Description")])
    worksource1 = StringField('Filter Source 1 - Option of format are (a.b.c.d/e or a.b.c.d or any)', [validators.Length(min=1, max=100, message="Format -------" )])
    workdest1 = StringField('Filter Destination 1 - Option of format are (a.b.c.d/e or a.b.c.d or any)', [validators.Length(min=1, max=100, message="Format -------")])
    workprot1 = StringField('Filter Protocol 1 - Option of format are (icmp or any or tcp/5000-5100)', [validators.Length(min=1, max=100, message="Format -------")])
    worksource2 = StringField('Filter Source 2 - Option of format are (a.b.c.d/e or a.b.c.d or any)', [validators.Length(min=0, max=100, message="Format -------")])
    workdest2 = StringField('Filter Destination 2 - Option of format are (a.b.c.d/e or a.b.c.d or any)', [validators.Length(min=0, max=100, message="Format -------")])
    workprot2 = StringField('Filter Protocol 2 - Option of format are (22 or 22,23,24 or any)', [validators.Length(min=0, max=100, message="Format -------")])


class DeleteAdminForm(Form):
    id = IntegerField('id', render_kw={'readonly': True})
    username = StringField('Login', render_kw={'readonly': True})
    useremail = EmailField('Email address', render_kw={'readonly': True})

class DeleteTapForm(Form):
    id = IntegerField('id', render_kw={'readonly': True})
    tapname = StringField('Tap Name', render_kw={'readonly': True})
    tapexpiry = StringField('Tap Expiry Time', render_kw={'readonly': True})

class DeleteAssignedTapForm(Form):
    id = IntegerField('id', render_kw={'readonly': True})
    tapname = StringField('Login', render_kw={'readonly': True})
    destination = StringField('Destination', render_kw={'readonly': True})

class DeleteAssignedWorkloadForm(Form):
    id = IntegerField('id', render_kw={'readonly': True})
    workloadname = StringField('Workload Name', render_kw={'readonly': True})

class DeleteTapTargetForm(Form):
    id = IntegerField('id', render_kw={'readonly': True})
    tapname = StringField('Tap Name', render_kw={'readonly': True})
    taptype = StringField('Tap Type', render_kw={'readonly': True})
    tapdest = StringField('Tap Destination', render_kw={'readonly': True})

class DeleteWorkloadTargetForm(Form):
    id = IntegerField('id', render_kw={'readonly': True})
    workloadname = StringField('Workload Name', render_kw={'readonly': True})
    workloaddesc = StringField('Workload Description Type', render_kw={'readonly': True})


class SetUpPsm(Form):
    ipman = StringField('Management IP', [validators.IPAddress(ipv4=True, message="Enter a valid IP Address")])
    adminuser = StringField('Admin UserName', [validators.Length(min=1, max=50)])
    adminpwd = PasswordField('Admin Password', [validators.Length(min=1, max=50)])


class Force(Form):
    checkbox = BooleanField('Agree?', validators=[validators.DataRequired(), ])


    
if __name__ == '__main__':
    # TODO:  need to build background job :
    initBackgroundProcs()
    app.secret_key = 'PensandoTapAsAService'
    app.run(debug=True, host=webhost, port=webport)
