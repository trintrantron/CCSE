from sqlalchemy import create_engine, Column, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.orm.exc import NoResultFound
from itertools import count
import hashlib
import bcrypt
from random import randint
from sqlalchemy_utils import StringEncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine
import time

f = open("db_key", "r")
key = f.readline()
f.close()

def load_id_count(table):
    f = open("{0}_id_counter".format(table), "r")
    count = int(f.readline())
    f.close()
    return(int(count))

def save_val(table):
            count = load_id_count(table)
            f = open("{0}_id_counter".format(table), "w")
            count += 1
            f.write(str(count))
            f.close()

###################################################################################################################
# Defining tables
###################################################################################################################

Base = declarative_base()
class db:

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Users
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    class Users(Base):
        id_counter = count(start = load_id_count("Users"), step = 1)
        def __init__(self, username, email, password, salt, user_type):
            self.user_id = str(next(self.id_counter))
            save_val("Users")
            self.username = username
            self.email = email
            self.password = password.decode("utf-8")
            self.user_type = user_type
            self.salt = salt

        __tablename__ = "Users"

        user_id = Column("User ID", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'), primary_key = True)
        username = Column("Username",StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        email = Column("Email", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        password = Column("Password", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        salt = Column("Salt", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        user_type = Column("User Type", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Products
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    class Products(Base):
        id_counter = count(start = load_id_count("Products"), step = 1)
        def __init__(self, productName, productDescription, productPrice):
            self.product_id = str(next(self.id_counter))
            save_val("Products")
            self.productName = productName
            self.productDescription = productDescription
            self.productPrice = productPrice

        __tablename__ = "Products"

        product_id = Column("Product ID", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'), primary_key = True)
        productName = Column("Product Name",StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        productDescription = Column("Product Description", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        productPrice = Column("Product Price", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Baskets
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    class Baskets(Base):
        id_counter = count(start = load_id_count("Baskets"), step = 1)
        def __init__(self, user_id, totalPrice, date):
            self.basket_id = str(next(self.id_counter))
            save_val("Baskets")
            self.user_id = user_id
            self.totalPrice = totalPrice
            date = date

        __tablename__ = "Baskets"

        basket_id = Column("Basket ID", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'), primary_key = True)
        user_id = Column("User ID",StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        totalPrice = Column("Total Price", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        date = Column("Date", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))

        def resetBasket(self): # sets the total price back to £0
            self.totalPrice = 0

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# User Orders
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    class UserOrders(Base):
        id_counter = count(start = load_id_count("UserOrders"), step = 1)
        def __init__(self, user_id, product_name, product_price):
            self.userOrder_id = str(next(self.id_counter))
            save_val("UserOrders")
            self.user_id = user_id
            self.product_name = product_name
            self.product_price = product_price

        __tablename__ = "UserOrders"

        userOrder_id = Column("User Order ID", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'), primary_key = True)
        user_id = Column("User ID",StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        product_name = Column("Product name", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        product_price = Column("Product price", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Purchase History
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    class PurchaseHistory(Base):
        id_counter = count(start = load_id_count("PurchaseHistory"), step = 1)
        def __init__(self, username, totalPrice, date):
            self.purhcase_id = str(next(self.id_counter))
            save_val("PurchaseHistory")
            self.username = username
            self.totalPrice = totalPrice
            self.date = date

        __tablename__ = "Purchase History"

        purhcase_id = Column("Purchase ID", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'), primary_key = True)
        username = Column("Username", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        totalPrice = Column("Total Price", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))
        date = Column("Date", StringEncryptedType(String(100), key, AesEngine, 'pkcs5'))

###################################################################################################################
# Creation
###################################################################################################################

engine = create_engine("sqlite:///securecart.db", echo = False)
Base.metadata.create_all(bind=engine)

Session = sessionmaker(bind=engine)
session = Session()

###################################################################################################################
# Defining Tasks
###################################################################################################################

class Task:

    # Checks if user exists and returns the object if they do
    def user_exists(username):
        try:
            user = session.query(db.Users).filter(db.Users.username==username).one()
            return(user)
        except NoResultFound as e:
            return(0)

    # Checks that the basket related to the given user ID has products in it
    def basket_not_empty(user_id):
        try:
            basket = session.query(db.Baskets).filter(db.Baskets.user_id==user_id).one()
            if float(basket.totalPrice) > 0:
                return(basket)
            return(0)
        except NoResultFound as e:
            return(0)

    # Checks if a product already exists with the product name, returns it if it does
    def product_exists(productName):
        try:
            product = session.query(db.Products).filter(db.Products.productName==productName).one()
            return(product)
        except NoResultFound as e:
            return(0)

    # Checks to see if the string given can be converted to a float
    def price_is_float(price):
        try:
            float(price)
            return(float(price))
        except ValueError:
            return(0)

    # Creates new row in the Products table with the given info
    def add_product(productName, productDescription, productPrice):
        product = db.Products(productName, productDescription, productPrice)
        session.add(product)
        session.commit()

    # Returns the Products table in a list
    def list_products():
        productTable = session.query(db.Products).all()
        products = []
        for product in productTable:
            products.append(product)
        return(products)

    # Checks user does not already exist and adds them to the system
    def add_user(username, email, password, user_type):
        if Task.user_exists(username) == 0:
            req = Task.check_password(password)
            if req[0] and len(username):
                salt = bcrypt.gensalt()
                bpass = password.encode('utf-8')
                hash = bcrypt.hashpw(bpass, salt)
                user = db.Users(username, email, hash, salt, user_type)
                date = time.strftime("%d-%m-%Y")
                basket = db.Baskets(user.user_id, "0.0", date) # This adds a basket for each new user created
                session.add(basket)
                session.add(user)
                session.commit()
                return(0) # Success
            return(req[1]) # Password doesnt meet requirements
        return(2) # User already exists

    # Checks that user exists and password is correct
    def login(username, password):
        user = Task.user_exists(username)
        if user != 0:
            bpass = password.encode('utf-8')
            result = bcrypt.checkpw(bpass, user.password.encode("utf-8"))
            if result:
                return((True, username))
        return((False, "Incorrect username or password"))

    # Retuns true if the password given meets the security requirements
    def check_password(password):
        if  len(password) < 8 or len(password) > 71: return (False, "Password does not meet the length requirements")
        if  not any(letter.isupper() for letter in password): return (False, "Password must contain a captial letter")
        if  not any(letter.islower() for letter in password): return (False, "Password must contain a lower case letter")
        if  not any(digit.isdigit() for digit in password): return (False, "Password must contain a number")
        special_char = "*%!@()[]$£?~#=+-/|"
        if not any(special in special_char for special in password): return (False, f"Password must contain a special character: {special_char}")
        return (True, "Valid Password")

    # Creates user order and updates the total price and date in the basket of given user
    def add_to_basket(username, productName):
        user = Task.user_exists(username)
        product = Task.product_exists(productName)
        if user != 0 and product != 0:
            userOrder = db.UserOrders(user.user_id, product.productName, product.productPrice) # This creates a user order with the user's id
            basket = session.query(db.Baskets).filter(db.Baskets.user_id==user.user_id).one() # This gets the basket for the correct user

            productPrice = float(product.productPrice) # This converts all price values into floats for calculations
            totalPrice = float(basket.totalPrice)
            totalPrice = totalPrice + productPrice
            totalPrice = str(round(totalPrice, 2)) # This converts the price back into a string for storage in the database

            basket.totalPrice = totalPrice
            basket.date = time.strftime("%d-%m-%Y")
            session.add(userOrder)
            session.commit()
            return(True, "Added to basket.")
        return(False, "Error")

    # This updates the total price of the contents of the user's basket and deletes the associated user order
    def remove_from_basket(userOrderId):
        userOrder = session.query(db.UserOrders).filter(db.UserOrders.userOrder_id==userOrderId).one()
        basket = session.query(db.Baskets).filter(db.Baskets.user_id==userOrder.user_id).one()
        product = session.query(db.Products).filter(db.Products.productName==userOrder.product_name).one()

        productPrice = float(product.productPrice) # This converts all price values into floats for calculations
        totalPrice = float(basket.totalPrice)
        totalPrice = totalPrice - productPrice
        totalPrice = str(round(totalPrice, 2)) # This converts the price back into a string for storage in the database

        basket.totalPrice = totalPrice
        basket.date = time.strftime("%d-%m-%Y")

        session.delete(userOrder)

        session.commit()
        return(True, "Removed from basket.")

    # This finds all user orders relating to the user given, returning them as a list
    def get_user_orders(username):
        user = Task.user_exists(username)
        if user != 0:
            userOrdersTable = session.query(db.UserOrders).all()
            userOrders = []
            for userOrder in userOrdersTable:
                if userOrder.user_id == user.user_id:
                    userOrders.append(userOrder)
            return(userOrders)
        return(0)

    # This finds the total price of the products in the user's basket and returns it
    def get_basket_total(username):
        user = Task.user_exists(username)
        if user != 0:
            basket = session.query(db.Baskets).filter(db.Baskets.user_id==user.user_id).one()
            totalPrice = basket.totalPrice
            return(totalPrice)
        return("")

    # This updates the purchase history table, resets the basket total price, and deletes all associated user orders
    def checkout(username):
        user = Task.user_exists(username)
        basket = Task.basket_not_empty(user.user_id)
        date = time.strftime("%d-%m-%Y")
        if basket != 0:
            purchase = db.PurchaseHistory(user.username, basket.totalPrice, date) # Add the purchase to history

            userOrders = session.query(db.UserOrders).filter(db.UserOrders.user_id==user.user_id).all() # Delete all products in the
            for order in userOrders:
                session.delete(order)

            session.add(purchase)
            db.Baskets.resetBasket(basket) # Reset the basket total
            session.commit()
            return(True)
        return(False)

    # This returns a list of all rows in the PurchaseHistory table
    def list_purchases():
        purchases = session.query(db.PurchaseHistory).all()
        print(purchases)
        return purchases

    # This reads the log file into an array for html display
    def read_log_file():
        log_file = open('login.log', 'r')
        lines = log_file.readlines()[1:]
        log = []
        for line in lines:
            log.append(line[:-1])
        return(log)
