# Item Catalog - Udacity  Full Stack ND

#### DESCRIPTION
Create a Item Catalog App so users can create, update and delete categories and items

### Project Structure
```
├── project.py
├── client_secrets.json
├── fb_client_secrets.json
├── database_setup.py
├── catalog.db
├── README.md
├── .gitignore
├── static
│   └── dist
│   └── plugins
└── templates
    └── auth
    |   └── login.html
    └── category
    |   └── category.html
    |   └── create.html
    |   └── delete.html
    |   └── edit.html
    └── item
    |    └── item.html
    |    └── create.html
    |    └── delete.html
    |    └── edit.html
    └── layout
    |   └── master.html
    └── index.html
```


#### RUNNING THE PROGRAM
To get started, I recommend you to download Vagrant, VirtualBox and VM configuration from links given below, 
* Download [Vagrant](https://www.vagrantup.com/) 
* Download [VirtualBox](https://virtualbox.org/wiki/Downloads)
* Download VM configuration [FSND-Virtual-Machine.zip](https://s3.amazonaws.com/video.udacity-data.com/topher/2018/April/5acfbfa3_fsnd-virtual-machine/fsnd-virtual-machine.zip)

**TO INSTALL AND MANAGE THE PROGRAM USING VIRTUAL MACHINE**
* Go to VM configuration folder
* Change to this directory in your terminal with `cd`
* Use `vagrant up` to bring the virtual machine online and `vagrant ssh` to login.
* Change directory to `/vagrant/catalog` folder
* Setup the database using `python database_setup.py`
* Run `python the project.py` to launch the project
* Open the project in the browser http://localhost:5000

### Project endpoints

### Home Page
`/`
 <br>
`/categories`
### Login Page
`/login`
### Category Items
`/categories/Category-ID` 
 <br>
`/categories/category_id/items`
### Create new Category
`/categories/create`
### Edit Category
`/categories/category_id/edit`
### Delete Category
`/categories/category_id/delete`
### Create new Item
`/categories/category_id/items/create`
### Edit Item
`/categories/category_id/items/item_id/edit`
### Delete Item
`/categories/category_id/items/item_id/delete`
### Item Details
`/categories/category_id/items/item_id`
### Categories Json
`/catalog.json`

### Frontend Template uses:
[AdminLTE 3](https://adminlte.io/themes/dev/AdminLTE/index.html)