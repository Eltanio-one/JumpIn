import unittest
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from src.app import app


class TestCase(unittest.TestCase):
    def setUp(self):
        # set up
        self.app = app
        # set up app context to allow access outside of
        self.app_ctxt = self.app.app_context()
        self.app_ctxt.push()

    def tearDown(self):
        # reset after test
        # drop all tables from in-memory db
        self.app_ctxt.pop()
        self.app = None
        self.app_ctxt = None

    def test_app(self):
        # test that app has been initialised
        assert self.app is not None
        assert app == self.app

    def test_signup_new_user(self):
        """Test signup page when a new user signs up."""

        result = self.app.post(
            "/register",
            data={
                "username": "tester",
                "email": "abc123@gmail.com",
                "date_of_birth": "01/01/1911",
                "password": "Password123@!",
                "name": "John Smith",
                "confirmation": "Password123@!",
                "languages": "af",
            },
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)


if __name__ == "__main__":
    unittest.main()
