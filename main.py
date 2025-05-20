from flask import Flask, render_template, request, redirect, url_for, session, g
from db import Task
import logging
import secrets
from flask_wtf import CSRFProtect
import os
import http.server
import git

from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
csrf = CSRFProtect(app)
http.server.BaseHTTPRequestHandler.version_string = lambda self: ""

###################################################################################################################
# Logger
###################################################################################################################

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler = RotatingFileHandler('login.log', maxBytes=1024 * 1024, backupCount=10)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.propagate = False

terminalLog = logging.getLogger('terminal')
server_handler = logging.StreamHandler()
server_handler.setFormatter(formatter)
server_handler.setLevel(logging.DEBUG) 
terminalLog.addHandler(server_handler)
terminalLog.setLevel(logging.DEBUG)

###################################################################################################################
# Session Key
###################################################################################################################

f = open("session_key", "r")
app.secret_key = f.readline()
f.close()

class Resource:
    def __init__(self, name, role):
        self.name = name
        self.role = role

class RBACSystem:
    def __init__(self):
        self.resources = []

    def add_resource(self, res_name, role):
        resource = Resource(res_name, role)
        self.resources.append(resource)
    
    def grant_access(self, username, resource_name):
        user = Task.user_exists(username)
        if user != 0:
            role = user.user_type
            for reasource in self.resources:
                if reasource.name == resource_name and (reasource.role == role or role == "adm"):
                    return(True)
        return(False)

###################################################################################################################
# Role based access control
###################################################################################################################

access = RBACSystem()
access.add_resource("user_homepage", "usr")
access.add_resource("view_products", "usr")
access.add_resource("about_us", "usr")
access.add_resource("contact_us", "usr")
access.add_resource("basket", "usr")
access.add_resource("checkout", "usr")
access.add_resource("checkout_success", "usr")
access.add_resource("checkout_final", "usr")
access.add_resource("add_to_basket", "usr")
access.add_resource("remove_from_basket", "usr")

access.add_resource("admin_homepage", "adm")
access.add_resource("add_product", "adm")
access.add_resource("view_login_activity", "adm")
access.add_resource("view_purchases", "adm")
access.add_resource("add_product_final", "usr")
access.add_resource("add_product_success", "adm")

@app.before_request
def make_session_permanent():
    session.permanent = True

###################################################################################################################
# Pages
###################################################################################################################

@app.route('/update_server', methods=['POST'])
def webhook():
    if request.method == 'POST':
        repo = git.Repo('/home/trin/mysite/')
        origin = repo.remotes.origin
        origin.pull()
        return 'Updated PythonAnywhere successfully', 200
    else:
        return 'Wrong event type', 400

@app.before_request
def generate_nonce():
    g.nonce = secrets.token_urlsafe(16)

@app.after_request
def add_csp_header(response):
    nonce = g.get('nonce')
    csp = (
        f"default-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"form-action 'self'; "
        f"frame-ancestors 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    return response
    
@app.route('/', methods=['GET', 'POST'])
def login_page():
    if not("message" in session):
        message = ""
    else:
        message = session["message"]
    if "message" in session:
        session.pop("message")
    session["logged_in"] = False
    return render_template('userandadminlogin.html', message=message)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    attempt = Task.login(username, password)
    if attempt[0] == True:
        user = Task.user_exists(username)
        session["username"] = user.username
        session["user_id"] = user.user_id
        session["email"] = user.email
        session["logged_in"] = True
        if user.user_type == "adm":
            app.logger.info(f"Successful login attempt: User '{username}' from IP {request.remote_addr}")
            return redirect('/admin_homepage') 
        app.logger.info(f"Successful login attempt: User '{username}' from IP {request.remote_addr}")
        return redirect('/user_homepage') 
    else:
        app.logger.warning(f"Failed login attempt: User '{username}' from IP {request.remote_addr}")
        session["message"] = attempt[1]
        return redirect("/")

@app.route('/signup', methods=['GET', 'POST']) 
def signup():
    if not("message" in session):
        message = ""
    else:
        message = session["message"]
    if "message" in session:
        session.pop("message")
    return render_template('usersignup.html', message=message)

@app.route('/signup_confirm', methods=['GET', 'POST']) 
def signup_confirm():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    passwordConf = request.form.get('confirm_password')
    if password == passwordConf:
        user_type = 'usr'
        add = Task.add_user(username, email, password, user_type)
        if add == 0: 
            app.logger.info(f"New user created: '{username}'")
            return redirect('/signup_success')
        if add == 2: 
            session["message"] = "That username is already taken."
            return redirect('/signup')
        session["message"] = add
        return redirect('/signup')
    session["message"] = "The passwords entered do not match."    
    return redirect('/signup')

@app.route('/signup_success', methods=['GET', 'POST'])
def signup_success():
    return render_template('signupsuccess.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    return render_template('forgotpassword.html')

@app.route('/user_homepage', methods=['GET', 'POST'])
def user_homepage():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "user_homepage")):
            username = session["username"]
            return render_template('userhomepage.html', username=username)
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/view_products', methods=['GET', 'POST'])
def view_products():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "view_products")):
            username = session["username"]
            products = Task.list_products()
            if not("message" in session):
                message = ""
            else:
                message = session["message"]
            if "message" in session:
                session.pop("message")
            return render_template('viewall.html', username=username, products=products, message=message)
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/about_us', methods=['GET', 'POST'])
def about_us():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "about_us")):
            username = session["username"]
            return render_template('aboutus.html', username=username)
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/contact_us', methods=['GET', 'POST'])
def contact_us():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "contact_us")):
            username = session["username"]
            return render_template('contactus.html', username=username)
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/basket', methods=['GET', 'POST'])
def basket():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "basket")):
            username = session["username"]
            userOrders = Task.get_user_orders(username)
            total = Task.get_basket_total(username)
            if total != "":
                if not("message" in session):
                    message = ""
                else:
                    message = session["message"]
                if "message" in session:
                    session.pop("message")
                return render_template('basket.html', username=username, total=total, message=message, userOrders=userOrders)
        else:
            return redirect("/")
    else:
        return redirect("/")
    
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "checkout")):
            username = session["username"]
            user = Task.user_exists(username)
            basket = Task.basket_not_empty(user_id=user.user_id)
            if basket != 0:
                total = Task.get_basket_total(username)
                if not("message" in session):
                    message = ""
                else:
                    message = session["message"]
                if "message" in session:
                    session.pop("message")
                return render_template('checkout.html', username=username, total=total, message=message)
            else:
                return redirect("/basket")
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/checkout_final', methods=['POST'])
def checkout_final():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "checkout_final")):
            card_number = request.form.get('card_number')
            expiry_date = request.form.get('expiry_date')
            cvc = request.form.get('CVC')
            if card_number.isdigit() and len(card_number) == 16:
                if cvc.isdigit() and len(cvc) == 3:
                        return redirect("/checkout_success")
                session["message"] = "CVC must be 3 digits long"
                return redirect("/checkout")
            session["message"] = "Account number must consist of 16 digits"
            return redirect("/checkout")
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/checkout_success', methods=['GET', 'POST'])
def checkout_success():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "checkout_success")):
            username = session["username"]
            attempt = Task.checkout(username)
            if attempt == True:
                return render_template('checkoutsuccess.html')
            else:
                return redirect("/basket")
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/admin_homepage', methods=['GET', 'POST'])
def admin_homepage():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "admin_homepage")):
            username = session["username"]
            products = Task.list_products()
            return render_template('adminhomepage.html', username=username, products=products)
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "add_product")):
            username = session["username"]
            if not("message" in session):
                message = ""
            else:
                message = session["message"]
            if "message" in session:
                session.pop("message")
            return render_template('addproduct.html', username=username, message=message)
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/view_login_activity', methods=['GET', 'POST'])
def view_login_activity():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "view_login_activity")):
            username = session["username"]
            logs = Task.read_log_file()
            return render_template('viewloginactivity.html', username=username, logs_data=logs)
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/view_purchases', methods=['GET', 'POST'])
def view_purchases():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "view_purchases")):
            purchases = Task.list_purchases()
            return render_template('viewpurchases.html', purchases=purchases)
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/add_product_final', methods=['POST']) 
def add_product_final():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "add_product_final")):
            product_name = request.form.get('product_name')
            product_description = request.form.get('product_description')
            product_price = request.form.get('product_price')
            price = Task.price_is_float(product_price)
            if Task.product_exists(productName=product_name) == 0:
                if price != 0:
                    Task.add_product(productName=product_name, productDescription=product_description, productPrice=product_price)
                    return redirect("/add_product_success")
                session["message"] = "Invalid price entered"
                return redirect("/add_product")
            session["message"] = "Product already exists"
            return redirect("/add_product")
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/add_product_success', methods=['GET', 'POST'])
def add_product_success():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "add_product_success")):
            return render_template('addproductsuccess.html')
        else:
            return redirect("/")
    else:
        return redirect("/") 

@app.route('/add_to_basket', methods=['GET', 'POST']) #!!!!!!!!
def add_to_basket():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "add_to_basket")):
            product = request.form.get('prodId')
            username = session["username"]
            attempt = Task.add_to_basket(username=username, productName=product)
            if attempt[0] == True:
                session["message"] = f"{product} added to basket!"
                return redirect("/view_products")
            else:
                session["message"] = f"Error, {product} not added to basket!"
                return redirect("/view_products")
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/remove_from_basket', methods=['GET', 'POST'])
def remove_from_basket():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "remove_from_basket")):
            userOrderId = request.form.get('userOrder')
            attempt = Task.remove_from_basket(userOrderId=userOrderId)
            if attempt[0] == True:
                session["message"] = "Removed from basket!"
                return redirect("/basket")
            else:
                session["message"] = "Error, not removed from basket!"
                return redirect("/basket")
        else:
            return redirect("/")
    else:
        return redirect("/")

@app.route('/logout', methods=['POST']) 
def logout():
    if session.get("logged_in") == True:
        if(access.grant_access(session["username"], "logout")):
            session["logged_in"] = False
            return redirect(url_for('login_page'))
        else:
            return redirect("/")
    else:
        return redirect("/")

if __name__ == '__main__':
    app.run(debug=False, port=8080)
