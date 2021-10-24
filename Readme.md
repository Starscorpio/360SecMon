<p align="center">
  <img width="500" src="https://github.com/Starscorpio/360SecMon/blob/main/gifs/360SecMon%20(2).gif" alt="Material Bread logo">
</p>

# Overview
<p align="center">
  <img width="800" src="https://github.com/Starscorpio/360SecMon/blob/main/gifs/Screenshot%202021-10-24%20at%205.51.13%20PM.png" alt="Material Bread logo">
</p>

# Features
* __Procurement:__ Procures security objects from users like SSL certificates, Public and Private SSH keys, Keystores like PKCS and JKS, etc.
* __Dashboard:__ Displays metadata of the security objects on an Analytical dashboard and provides an insight about the risk and mitigation/remedition actions. It also includes bar chart and trend line to get a specific numerical value and understand the overall trend.
* __Notification system:__ Notification system available for users to notify changes that need to be made.
* __CRUD:__ CRUD (Create, Retrieve, Update, Delete) functionality also available for all end users.

# Prerequisities
Python | Django
------------ | -------------
<img src="https://github.com/Starscorpio/360SecMon/blob/main/gifs/Python_final.jpeg" width="300" height="200"> | <img src="https://github.com/Starscorpio/360SecMon/blob/main/gifs/django.png" width="300" height="300">
`sudo apt-get install python3.8 python3-pip` | `python3 -m django.py`


* python3
* pip3
* django framework
* for installation of other libraries, packages and modules use requirements.txt

## Installation
* Install python:-
	* `sudo apt install python3-pip` (Linux)
	* Install python directly from website (along with the pip3 tool): python.org (windows)

* Drag/Copy the entire folder over to your filesystem.

* Install django:-
	* `pip install django` or `pip3 install django`

* Or use:
	* `pip install -r requirements.txt`

* Database migration:- (To setup manually, refer to dbsetup.txt)
	* Use model.py to created database models
	* Run commands to migrate database:-
		* `python3 manage.py makemigrations`
		* `python3 manage.py migrate`
	* If error says "table already exists" use command:
		* `python3 manage.py migrate --fake securecheck(app name)`

* To run the project use command:
	* `python3 manage.py runserver`
