import os

# Set the RSA_KEYS_DIR to a local directory for tests
# This must be done before importing main, as main loads .env
os.environ["RSA_KEYS_DIR"] = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")
