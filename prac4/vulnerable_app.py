from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Insecure storage of credentials (for demonstration ONLY - NEVER do this in real apps)
USERS = {
    "testuser": "password123",
    "admin": "adminpass",
    "demo": "demo123"
}

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in USERS and USERS[username] == password:
            return render_template('login_success.html', username=username)  # Successful login page
        else:
            error = 'Invalid credentials. Please try again.'

    return render_template('login_form.html', error=error)  # Login form page

@app.route('/login_success') # Just for demonstration, not directly used in attack
def login_success():
    username = request.args.get('username')
    return render_template('login_success.html', username=username)


if __name__ == '__main__':
    app.run(debug=True, port=5000) # Run locally on port 5000, debug mode for development