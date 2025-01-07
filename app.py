import os
from flask import Flask, redirect, url_for, session, request, jsonify, render_template, flash
from authlib.integrations.flask_client import OAuth
import requests
import base64
import logging

# Initialize Flask app
app = Flask(__name__, template_folder='client_templates', static_folder='client_static')

# Set secret key for session management
app.config['SECRET_KEY'] = os.environ.get('CLIENT_SECRET_KEY') or 'your-client-secret-key'

# Configure OAuth client
oauth = OAuth(app)
idp_oauth = oauth.register(
    name='idp',
    client_id=os.environ.get('CLIENT_ID'),  # Replace with your actual CLIENT_ID
    client_secret=os.environ.get('CLIENT_SECRET'),  # Replace with your actual CLIENT_SECRET
    access_token_url='https://idpproject-d92b6ed87815.herokuapp.com/token',
    authorize_url='https://idpproject-d92b6ed87815.herokuapp.com/authorize',
    api_base_url='https://idpproject-d92b6ed87815.herokuapp.com/',
    client_kwargs={
        'scope': 'openid profile email',
        'token_endpoint_auth_method': 'client_secret_basic'  # Ensure this is set to 'client_secret_basic'
    },
)

# Configure logging
logging.basicConfig(level=logging.INFO)

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(32).hex()
    return session['csrf_token']

# Home route
@app.route('/')
def home():
    if 'user' in session:
        user = session['user']
        if 'profile' not in user:
            # Fetch user profile if not already in session
            try:
                response = idp_oauth.get('userinfo')
                logging.info(f"Response from IDP: Status Code: {response.status_code}, Response: {response.text}")
                if response.status_code == 200:
                    user['profile'] = response.json()
                    session['user'] = user
                else:
                    logging.error(f"Error fetching user profile. Status Code: {response.status_code}, Response: {response.text}")
                    flash('Error fetching user profile.', 'error')
                    return redirect(url_for('login'))
            except Exception as e:
                logging.error(f"Error fetching user profile: {str(e)}")
                flash('Error fetching user profile.', 'error')
                return redirect(url_for('login'))
        return render_template('dashboard.html', user=user)
    else:
        return render_template('home.html')

# Login route to initiate OAuth 2.0 flow
@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    csrf_token = generate_csrf_token()  # Generate CSRF token
    logging.info(f"Redirect URI: {redirect_uri}, CSRF Token: {csrf_token}")
    return idp_oauth.authorize_redirect(redirect_uri, state=csrf_token)  # Pass CSRF token as the state parameter

# Authorize route to handle the callback from IDP
@app.route('/authorize')
def authorize():
    try:
        # Log incoming request parameters for debugging
        logging.info(f"Incoming request parameters: {request.args}")

        csrf_token = session.get('csrf_token')
        if not csrf_token:
            logging.error("CSRF token not set in session.")
            #return redirect(url_for('home'))
        logging.info(f"CSRF token for authorize: {csrf_token}")

        data = {
            'grant_type': 'authorization_code',
            'code': request.args.get('code'),
            'redirect_uri': url_for('authorize', _external=True),
            'csrf_token': csrf_token
        }

        logging.info(f"Token request data: {data}")

        headers = {
            'Authorization': f"Basic {base64.b64encode(f'{os.environ.get('CLIENT_ID')}:{os.environ.get('CLIENT_SECRET')}'.encode()).decode()}",
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post('https://idpproject-d92b6ed87815.herokuapp.com/token', data=data, headers=headers)
        logging.info(f"Token exchange response status code: {response.status_code}")
        logging.info(f"Token exchange response text: {response.text}")

        if response.status_code != 200:
            logging.error("Token exchange failed.")
            return redirect(url_for('home'))

        token_response = response.json()
        logging.info(f"Token response: {token_response}")

        if 'access_token' in token_response:
            session['user'] = {
                'access_token': token_response['access_token'],
                'refresh_token': token_response.get('refresh_token'),
                'token_type': token_response['token_type'],
                'scope': token_response['scope']
            }
            logging.info(f"Access Token: {session['user']['access_token']}")
            logging.info(f"Refresh Token: {session['user'].get('refresh_token')}")
            return redirect(url_for('dashboard'))
        else:
            logging.error("Access token not found in response.")
            flash('Authorization failed.', 'error')
            return redirect(url_for('home'))

    except Exception as e:
        logging.error(f"Error during authorization: {str(e)}")
        flash('Authorization failed due to an error.', 'error')
        return redirect(url_for('home'))

# Dashboard route to display user information
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        logging.info('User not in session, redirecting to login.')
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))
    # Check if access token is present
    if 'access_token' not in session['user']:
        logging.info('Access token missing in session, redirecting to login.')
        flash('Access token is missing. Please log in again.', 'error')
        return redirect(url_for('login'))

    # Fetch user profile from IDP using the access token
    try:
        logging.info('Fetching user profile from IDP.')
        access_token = session['user']['access_token']
        response = requests.get(
            'https://idpproject-d92b6ed87815.herokuapp.com/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        logging.info(f"Response from IDP: Status Code: {response.status_code}, Response: {response.text}")
        if response.status_code == 200:
            user_info = response.json()
            session['user']['profile'] = user_info
            logging.info(f"User Profile: {user_info}")
            return render_template('dashboard.html', user=session['user'])
        else:
            logging.error(f"Error fetching user profile. Status Code: {response.status_code}, Response: {response.text}")
            flash('Error fetching user profile.', 'error')
            return redirect(url_for('login'))
    except Exception as e:
        logging.error(f"Error fetching user profile: {str(e)}")
        flash('Error fetching user profile.', 'error')
        return redirect(url_for('login'))

# Logout route to clear session and log out the user
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, ssl_context='adhoc')  # Run with SSL context for HTTPS