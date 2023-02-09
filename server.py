from flask import Flask, redirect, url_for, render_template, request, session, flash
import sys, hashlib, uuid, binascii, os, json, random
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy



app = Flask(__name__)
app.secret_key = "secretkeyteehee"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False



db = SQLAlchemy(app)


class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    pwdsalt = db.Column(db.String(100))
    pwdhash = db.Column(db.String(100))
    email = db.Column(db.String(100))

    def __init__(self, name, pwdsalt, pwdhash, email):
        self.name = name
        self.pwdsalt = pwdsalt
        self.pwdhash = pwdhash
        self.email = email


port = 8000 if len(sys.argv) == 1 else sys.argv[1]



@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("user"))
    return redirect(url_for("login"))

@app.route("/view")
def view():
    return render_template("view.html", values=users.query.all())
    
@app.route("/test")
def test():
    return render_template("new.html")

@app.route("/register", methods=["POST", "GET"])
def register():
    if "user" in session:
        flash("You are already logged in!")
        return redirect(url_for("user"))

    if request.method == "POST":
        user = request.form.get("nm")
        pwa = request.form.get("pwa")
        pwb = request.form.get("pwb")

        if (user == "") or (pwa == "") or (pwb == ""):
            flash("Please complete all fields.")
            return redirect(url_for("register"))
        
        if pwa != pwb:
            flash("Passwords do not match!")
            return redirect(url_for("register"))

        if users.query.filter_by(name=user).first():
            flash("Username taken!")
            return redirect(url_for("register"))


        
        session["user"] = user
        create_user_db(str(user))
        hashed_pw = hash_password(pwa)
        usr = users(user, hashed_pw["salt"], hashed_pw["pwdhash"], None)
        db.session.add(usr)
        db.session.commit()

        flash("Registration successful")
        return redirect(url_for("user"))


        

    else:
        return render_template("register.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        
        user = request.form["nm"]
        pwd = request.form.get("pwd")
        remember = request.form.get("rmb")
        
        
        found_user = users.query.filter_by(name=user).first()
        
        if found_user:
            hashed_pw = {
                "salt": found_user.pwdsalt,
                "pwdhash": found_user.pwdhash
            }
            if verify_password(hashed_pw,pwd):

                session["user"] = user

                user_db = import_user_db(user)


                flash("Login Successful!")
                return redirect(url_for("user"))

        flash("Invalid details")
        return redirect(url_for("login"))
            

        
    else:
        if "user" in session:
            flash("You are already logged in!")
            return redirect(url_for("user"))
        
        return render_template("login.html")


@app.route("/user", methods=["POST", "GET"])
def user():
    email = None
    if "user" in session:
        user = session["user"]

        if not has_key(user):
            flash("You must first generate encryption keys!")
            return redirect(url_for("generate_key"))

        if request.method == "POST":
            friend = request.form["friend-req"]
            if friend:
                if send_friend_request(user,friend):
                    flash("Friend request sent successfully")
                else:
                    flash("Error, user does not exist, you are already friends, or request already exists.")
        else:
            if "email" in session:
                email = session["email"]

        
        user_db = import_user_db(user)

        return render_template("user.html", name=user, email=email, vaqlues=users.query.all(), db=user_db)
    else:
        flash("You are not logged in!")
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    if not "user" in session:
        return redirect(url_for("login"))
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/friendrequest/<friend>/accept")
def accept_friend_request(friend):
    if not "user" in session:
        return redirect(url_for("login"))
    user = session["user"]

    if not validate_friend_request(user,friend):
        return redirect(url_for("user"))

    user_db = import_user_db(user)
    friend_db = import_user_db(friend)

    for item in user_db["friend-requests"]:
        if item["user"] == friend:
            user_db["friend-requests"].remove(item)
    for item in friend_db["friend-requests"]:
        if item["user"] == user:
            friend_db["friend-requests"].remove(item)

    user_db["friends"].append(friend)
    friend_db["friends"].append(user)

    export_user_db(user,user_db)
    export_user_db(friend,friend_db)

    flash("Friend request accepted.")
    return redirect(url_for("user"))

@app.route("/friendrequest/<friend>/decline")
def decline_friend_request(friend):
    if not "user" in session:
        return redirect(url_for("login"))
    user = session["user"]

    if not validate_friend_request(user,friend):
        return redirect(url_for("user"))

    user_db = import_user_db(user)
    friend_db = import_user_db(friend)

    for item in user_db["friend-requests"]:
        if item["user"] == friend:
            user_db["friend-requests"].remove(item)
    for item in friend_db["friend-requests"]:
        if item["user"] == user:
            friend_db["friend-requests"].remove(item)

    export_user_db(user,user_db)
    export_user_db(friend,friend_db)

    flash("Friend request declined.")
    return redirect(url_for("user"))
    
@app.route("/friend/<friend>/delete")
def delete_friend(friend):
    if not "user" in session:
        flash("You are not logged in!")
        return redirect(url_for("login"))
    user = session["user"]

    if not is_friend(user,friend):
        flash("This user is not your friend")
        return redirect(url_for("user"))

    user_db = import_user_db(user)
    friend_db = import_user_db(friend)

    user_db["friends"].remove(friend)
    friend_db["friends"].remove(user)

    export_user_db(user,user_db)
    export_user_db(friend,friend_db)

    flash("Friend deleted.")
    return redirect(url_for("user"))

@app.route("/message/<friend>", methods=["POST", "GET"])
def message(friend):
    if not "user" in session:
        flash("You must be logged in to message!")
        return(redirect(url_for("login")))
    
    user = session["user"]

    if not is_friend(session["user"],friend):
        flash("Error: Invalid User")
        return redirect(url_for("user"))

    user_db = import_user_db(user)
    friend_db = import_user_db(friend)

    sent = []
    i  = len(user_db["messages"])-1
    while i >= 0:
        if user_db["messages"][i]["to"] == friend:
            sent.append(user_db["messages"][i])
        i -= 1
    """for message in user_db["messages"]:
        if message["to"] == friend:
            sent.append(message)"""

    received = []
    i  = len(friend_db["messages"])-1
    while i >= 0:
        if friend_db["messages"][i]["to"] == user:
            received.append(friend_db["messages"][i])
        i -= 1

    if request.method == "POST":
        send_message(user,friend,request.form["sendMessage"])
        flash("Message sent!")
        return redirect('/message/'+friend)

    friend_pk = friend_db["publickey"]
        

    
    return  render_template("message.html", user=user, friend=friend, sent=sent, received=received, friend_pk=friend_pk)

@app.route('/generatekey', methods=["POST", "GET"])
def generate_key():
    if not "user" in session:
        flash("You must be logged in to do this!")
        return(redirect(url_for('login')))
    
    user = session["user"]

    if request.method == "POST":
        key = {
            "X": request.form.get("pubX"),
            "Y": request.form.get("pubY")
        }

        db = import_user_db(user)
        db["publickey"] = key
        export_user_db(user,db)

        flash("Key saved successfully!")
        return redirect(url_for("user"))
    return render_template("generatekey.html", user=user)

@app.errorhandler(404)
def page_not_found(e):
    flash("Error 404, page does not exist!")
    return redirect(url_for("user"))


    

def hash_password(password):

    salt = binascii.b2a_base64(hashlib.sha256(os.urandom(60)).digest()).strip()
    pwdhash = binascii.b2a_base64(hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 10000)).strip().decode()
    return { 'salt': salt.decode(), 'pwdhash': pwdhash } 

def verify_password(stored_password, provided_password):

    pwdhash = hashlib.pbkdf2_hmac('sha256', 
                                  provided_password.encode('utf-8'), 
                                  stored_password['salt'].encode(), 
                                  10000)
    return pwdhash == binascii.a2b_base64(stored_password['pwdhash']) 

def create_user_db(username):
    username = str(username)
    db = {
    "friends": [],
    "publickey": {},
    "friend-requests": [],
    "messages": []
    }

    with open('users/'+username+'.json', 'w') as outfile:
        json.dump(db, outfile, indent=4)

def export_user_db(username,db):
    username = str(username)

    with open('users/'+username+'.json', 'w') as outfile:
        json.dump(db, outfile, indent=4)

def import_user_db(username):
    username = str(username)
    db = {}

    try:
        with open('users/'+username+'.json') as infile:
            db = json.loads(infile.read())
    except:
        pass

    return db

def send_friend_request(username,friend):
    username = str(username)
    friend = str(friend)


    user_db = import_user_db(username)
    friend_db = import_user_db(friend)


    if is_friend(username,friend):
        return False

    if username == friend:
        return False

    if friend_db == {}:
        return False

    for friend_request in user_db.get('friend-requests'):
        if friend_request["user"] == friend:
            return False
    
    user_db["friend-requests"].append(
        {
            "user":friend,
            "sent":True
        }
    )
    friend_db["friend-requests"].append(
        {
            "user":username,
            "sent":False
        }
    )

    export_user_db(username,user_db)
    export_user_db(friend,friend_db)

    return True


def validate_friend_request(username,friend):
    username = str(username)
    friend = str(friend)


    db = import_user_db(username)

    for item in db["friend-requests"]:
        if item["user"] == friend:
            return True
    
    return False

def is_friend(username,friend):
    username = str(username)
    friend = str(friend)


    db = import_user_db(username)

    if friend in db["friends"]:
        return True
    
    return False

def send_message(username,friend,message):
    username = str(username)
    friend = str(friend)
    message = str(message)

    user_db = import_user_db(username)

    time = datetime.now().strftime("%-I:%M %p, %a %-d %b %Y")

    message_obj = {
        "to":friend,
        "time":time,
        "message":message
    }

    user_db["messages"].append(message_obj)

    export_user_db(username,user_db)

def has_key(username):
    db = import_user_db(username)
    print(db)
    if db["publickey"] != {}:
        return True
    return False

"""@app.template_filter('fromtimestamp')
def fromtimestamp(s):
    date = datetime.fromtimestamp(s)
    return date"""




    


if __name__ == "__main__":
    db.create_all()
    app.run(
        ssl_context=('chatswould.test.crt','chatswould.test.key'),
        debug=True,
        host='0.0.0.0',
        port=port)