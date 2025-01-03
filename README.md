This program is a very basic demo of a login system, using flask and sqlite.  It does not verify emails, or support 2FA, and currently has no mechanism for resetting passwords.  That being said, the basic parts are functional.

# Quickstart

First, create a virtual environment and activate it.

```
python -m venv venv
source venv/bin/activate
```

Then install the required packages in the venv.

```
pip install -r requirements.txt
```

Then, use flask to run the program.

```
python -m flask --app src/app.py run
```

