#!/usr/bin/env python3
import random
import string
from flask import Flask, render_template
from flask import request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
# New imports for this step
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from sqlalchemy.orm import lazyload

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


# google login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return 'success'


# facebook login
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?' \
          'grant_type=fb_exchange_token&' \
          'client_id=%s&client_secret=%s&fb_exchange_token=%s' \
          % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?' \
          'access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    login_session['access_token'] = token

    url = 'https://graph.facebook.com/v2.8/me/picture?' \
          'access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    flash("Now logged in as %s" % login_session['username'])
    return 'success'


# logout
@app.route('/logout')
def logout():
    if login_session['provider'] == 'google':
        access_token = login_session.get('access_token')
        if access_token is None:
            print('Access Token is None')
            response = make_response(
                json.dumps('Current user not connected.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' %\
              login_session['access_token']
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if result['status'] == '200':
            del login_session['access_token']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['provider']
            del login_session['user_id']
            response = make_response(
                json.dumps('Successfully disconnected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return redirect(url_for('catalog'))
        else:
            response = make_response(
                json.dumps('Failed to revoke token for given user.', 400))
            response.headers['Content-Type'] = 'application/json'
            return response
    if login_session['provider'] == 'facebook':
        facebook_id = login_session['facebook_id']
        # The access token must me included to successfully logout
        access_token = login_session['access_token']
        url = 'https://graph.facebook.com/%s/permissions?' \
              'access_token=%s' % (facebook_id, access_token)

        h = httplib2.Http()
        result = h.request(url, 'DELETE')[1]
        return result


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('auth/login.html', STATE=state)


@app.route('/categories')
@app.route('/')
def catalog():
    # Get all Categories
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template('index.html',
                           categories=categories, items=items,
                           login_session=login_session)


@app.route('/categories/<int:category_id>')
@app.route('/categories/<int:category_id>/items')
def category(category_id):
    # Get category by id
    category_query = session.query(Category).filter_by(id=category_id).one()
    # Get all items related to this category
    items = session.query(Item).filter_by(category_id=category_id).all()
    return render_template('category/category.html',
                           category=category_query, items=items,
                           login_session=login_session)


# categories routes

# create new Category
@app.route('/categories/create',
           methods=['GET', 'POST'])
def createCategory():
    # Check if user login
    if 'user_id' not in login_session:
        return redirect(url_for('showLogin'))

    if request.method == "GET":
        return render_template('category/create.html')
    if request.method == "POST":
        if not request.form['name']:
            flash("Category Name is required")
            return redirect(url_for('createCategory'))

        # Create New Category
        new_category = Category(name=request.form['name'],
                                user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        flash('Category has been created successfully')
        return redirect(url_for("catalog"))


# Edit Category
@app.route('/categories/<int:category_id>/edit', methods=['POST', 'GET'])
def editCategory(category_id):
    # Get Category by id
    category_query = session.query(Category).filter_by(id=category_id).one()
    # check user is login and he is the owner of this category
    if 'user_id' in login_session and login_session['user_id'] ==\
            category_query.user_id:
        if request.method == "GET":
            return render_template('category/edit.html',
                                   category=category_query)
        if request.method == "POST":
            # Category name Validation
            if not request.form['name']:
                flash("Category Name cannot be empty")
                return redirect(url_for('editCategory',
                                        category_id=category_query.id))
            category_query.name = request.form['name']
            flash("Category has been update successfully")
            return redirect(url_for('catalog'))
        return 'Error'
    return 'unauthorized'


# Delete Category
@app.route('/categories/<int:category_id>/delete', methods=['POST', 'GET'])
def deleteCategory(category_id):
    # Get Category by id
    category_query = session.query(Category).filter_by(id=category_id).one()
    # check user is login and he is the owner of this category
    if 'user_id' in login_session and login_session['user_id'] ==\
            category_query.user_id:
        if request.method == 'GET':
            return render_template('category/delete.html',
                                   login_session=login_session,
                                   category=category_query)
        if request.method == 'POST':
            session.delete(category_query)
            session.commit()
            flash('Category has been deleted successfully')
            return redirect(url_for('catalog'))
        return 'unauthorized'


# Items Routes
# Create New Item
@app.route('/categories/<int:category_id>/items/create',
           methods=["GET", "POST"])
def createItem(category_id):
    # Get Category by id
    category_query = session.query(Category).filter_by(id=category_id).one()

    # check user is login and he is the owner of this Item
    if not login_session['user_id'] == category_query.user_id:
        return 'you don\'t have permission to create new item' \
               ' under %s '.category_query.name

    if request.method == 'GET':
        return render_template('item/create.html',
                               category=category_query)

    if request.method == "POST":
        if not request.form['name']:
            flash("Name is required")
            return redirect(url_for('createItem',
                                    category_id=category_query.id))
        if not request.form['description']:
            flash("Description is required")
            return redirect(url_for('createItem',
                                    category_id=category_query.id))
        # create new item
        new_item = Item(name=request.form['name'],
                        description=request.form['description'],
                        category_id=category_query.id)
        session.add(new_item)
        session.commit()
        flash('Item has been created successfully')
        return redirect(url_for("category", category_id=category_query.id))


# Edit Item
@app.route('/categories/<int:category_id>/items/<int:item_id>/edit',
           methods=["GET", "POST"])
def editItem(category_id, item_id):
    # get item from database
    item_query = session.query(Item).filter_by(id=item_id).one()
    # get category from database
    category_query = session.query(Category).filter_by(id=category_id).one()
    # check user is login and he is the owner of this Item
    if 'user_id' in login_session and login_session['user_id'] ==\
            item_query.category.user_id:
        if request.method == "GET":
            return render_template('item/edit.html',
                                   category=category_query, item=item_query)
        if request.method == "POST":
            # Form validation
            if not request.form['name']:
                flash("Item Name cannot be empty")
                return redirect(url_for('editItem', category_id=category_id,
                                        item_id=item_id))
            if not request.form['description']:
                flash("Item description cannot be empty")
                return redirect(url_for('editItem', category_id=category_id,
                                        item_id=item_id))

            item_query.name = request.form['name']
            item_query.description = request.form['description']
            flash("Item has been update successfully")
            return redirect(url_for("category", category_id=category_id))
        return 'Error'
    return 'unauthorized'


# Delete Item
@app.route('/categories/<int:category_id>/items/<int:item_id>/delete',
           methods=["GET", "POST"])
def deleteItem(category_id, item_id):
    # Get Item from database
    item_query = session.query(Item).filter_by(id=item_id).one()
    # Check if user login and he is the owner
    if 'user_id' in login_session and login_session['user_id']\
            == item_query.category.user_id:
        if request.method == 'GET':
            return render_template('item/delete.html',
                                   category=category_id, item=item_query)
        if request.method == 'POST':
            session.delete(item_query)
            session.commit()
            flash('Item has been deleted successfully')
            return redirect(url_for("category", category_id=category_id))
        return 'unauthorized'


# show item details
@app.route('/categories/<int:category_id>/items/<int:item_id>',
           methods=["GET"])
def item(category_id, item_id):
    # Get item details
    item_query = session.query(Item).filter_by(id=item_id).one()
    # Get category details
    category_query = session.query(Category).filter_by(id=category_id).one()
    return render_template('item/item.html',
                           category=category_query, item=item_query)


# return all categories in json
@app.route('/catalog.json')
def catalogJson():
    categories = session.query(Category).options(lazyload('items')).all()
    return make_response(jsonify(
        categories=[i.serialize for i in categories]), 200)


# user functions
def createUser(user):
    new_user = User(name=user['username'], email=user[
        'email'], picture=user['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=user['email']).one()
    return user.id


# Get user ID  if user exist
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


if __name__ == '__main__':
    app.secret_key = 'secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000, threaded=False)
