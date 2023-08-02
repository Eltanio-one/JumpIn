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


if __name__ == "__main__":
    unittest.main()
