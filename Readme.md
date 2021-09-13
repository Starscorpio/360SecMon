# 360 Degree Security Monitoring of an Enterprise

## Prerequisities to setup the project:-
* python3
* pip3
* django framework

## Steps to setup the project:-
* Install python:-
	* sudo apt install python3-pip (Linux)
	* Install python directly from website (along with the pip3 tool): python.org (windows)

* Drag/Copy the entire folder over to your filesystem.

* Install django:-
	* pip install django or pip3 install django

* Or use:
	* pip install -r requirements.txt

* Setup MYSQL database:-
	* Login to mysql as root user -> mysql -u root -p 'user_password'
	* You can create another user if necessary and then grant privileges -> GRANT ALL PRIVILEGES ON database_name.* TO 'username'@'localhost';
	* Change root user's password if needed and set mysql_native_password -> ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '<password>';
	* Create a database called 'secmon' -> CREATE DATABASE databasename;
	* Create a table inside the database called 'finaldata' -> CREATE TABLE finaldata (ID INT, username VARCHAR(50), email VARCHAR(50), month VARCHAR(10), Not_Valid_Before VARCHAR(50), Not_Valid_After VARCHAR(50), Subject VARCHAR(50), Encryption VARCHAR(50), Status VARCHAR(50), Revocation_status VARCHAR(50));
	* Create another table called 'mynewestkeysdata' -> CREATE TABLE finaldata (id INT, month VARCHAR(10), username VARCHAR(50), email VARCHAR(50), Number_of_bits INT, Encryption VARCHAR(50));
	* Got to file Settings.py and in DATABASES section change the parameters according to your database info.

* To create superuser user the command:-
	* python3 manage.py createsuperuser (not necessary)


* Run commands to migrate database:-
	* Go to the root of your project and in the terminal use the following commands:
		* python3 manage.py makemigrations
		* python3 manage.py migrate
	* If error says table already exists use command:
		* python3 manage.py migrate --fake securecheck(app name)

* To run the project use command:
	* python3 manage.py runserver
