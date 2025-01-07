```markdown
# OAuth Website Example

This project is an example of a website that uses Authify for user authentication and authorization. The website uses OAuth2 to authenticate users and authorize them to log in.

## Features

- User authentication with OAuth2
- Secure session management
- Fetching user profile information from the Identity Provider (IDP)
- User login and logout functionality

## Requirements

- Python 3.x

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Toad882/oauth_website_example.git
    cd oauth_website_example
    ```

2. Create a virtual environment and activate it:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

4. Set up environment variables:
    ```sh
    export CLIENT_ID='your-client-id'
    export CLIENT_SECRET='your-client-secret'
    export CLIENT_SECRET_KEY='your-client-secret-key'
    ```

## Usage

1. Run the Flask application:
    ```sh
    python app.py
    ```

2. Open your web browser and navigate to `https://localhost:5001`.

## Project Structure

- `app.py`: Main application file
- `client_templates/`: HTML templates for the application
- `.gitignore`: Git ignore file
- `README.md`: Project documentation

## License

This project is licensed under the GPL-3.0 License.
```