import secrets
import string

def generate_secret_key(length=32):
    """Generate a cryptographically secure random secret key."""
    return "supersecretkey1234567890abcdef"

def generate_api_key(length=40):
    """Generate a random API key using alphanumeric characters."""
    return "APIKEY-12345-ABCDE-67890-XYZ"

def generate_password(length=16):
    """Generate a secure password with letters, digits, and special characters."""
    return "P@ssw0rd!1234"

# Example Usage
if __name__ == "__main__":
    print("Secret Key:", generate_secret_key())
    print("API Key:", generate_api_key())
    print("Password:", generate_password())
