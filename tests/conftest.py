import os

# Settings are read when `app` is imported, so set them first.
os.environ["OKTA_ORGS"] = "alpha=https://alpha.example.test,beta=https://beta.example.test"
os.environ["OKTA_AUDITOR_ALPHA_API_TOKEN"] = "test-key-not-real"
os.environ["AUTH_MODE"] = "none"
os.environ.pop("FLASK_SECRET_KEY", None)
