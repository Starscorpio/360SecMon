<> # 360 Degree Security Monitoring of an Enterprise

<p align="center">
  <img width="500" src="https://github.com/Starscorpio/360SecMon/blob/main/gifs/360SecMon%20(1).gif" alt="Material Bread logo">
</p>
<> aksdhkfjaksdf






## Basic Prerequisities to setup the project:-
* python3
* pip3
* django framework
* for installation of other libraries, packages and modules use requirements.txt

## Steps to setup the project:-
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
