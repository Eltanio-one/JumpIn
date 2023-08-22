import unittest
import sys
import os
import flask_testing
from flask import Flask
from classes import UserService
from werkzeug.security import generate_password_hash

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from app import app


class TestCase(flask_testing.TestCase):
    def create_app(self):
        """Create app to enable flask_testing"""
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.config["LOGIN_DISABLED"] = True
        return self.app

    def setUp(self):
        """Set up app"""
        self.app = app
        self.client = app.test_client()
        self.app.config["TESTING"] = True
        self.app.config["LOGIN_DISABLED"] = True
        with self.client.session_transaction() as session:
            user_service = UserService
            new_user = user_service.register_user(
                username="test",
                email="test@gmail.com",
                name="test",
                date_of_birth="11/11/1111",
                account_creation="18/08/23",
                hashed_password=generate_password_hash("Password123!"),
            )
            session["user"] = new_user
            session["user_id"] = 7
        self.app_ctxt = self.app.app_context()
        self.app_ctxt.push()

    def test_app(self):
        """Test app initialisation"""
        assert self.app is not None
        assert app == self.app

    def test_index(self):
        """Test index"""
        result = self.client.get("/")
        self.assertEqual(result.status_code, 200)

    def test_user_register(self):
        """Test user registering (GET)"""
        result = self.client.get("/register")
        self.assertEqual(result.status_code, 200)

        """Test user registering (POST)"""
        result = self.client.post(
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

    def test_user_login(self):
        """Test user login (GET)"""
        result = self.client.get("/login")
        self.assertEqual(result.status_code, 200)

        """Test user login (POST)"""
        result = self.client.post(
            "/login",
            data={"username": "tester", "password": "Password123@!"},
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

    def test_delete_user(self):
        """Test deleting user account (GET)"""
        result = self.client.get("/delete_user")
        self.assertEqual(result.status_code, 200)

        """Test deleting user account (POST)"""
        result = self.client.post(
            "/delete_user", data={"password_delete": "test"}, follow_redirects=True
        )
        self.assertEqual(result.status_code, 200)

    def test_change_password(self):
        """Test changing user password"""
        result = self.client.post(
            "/change_password",
            data={
                "password_old": "Password123!@",
                "password_new": "Wordpass123!@",
                "confirmation": "Wordpass123!@",
            },
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

    def test_favourite_gym(self):
        """Test assigning a favourite a gym"""
        result = self.client.post(
            "/favourite_gym",
            data={"favourite_gym": "The Gym"},
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

    def test_session_methods(self):
        """Test planning a session (GET)"""
        result = self.client.get("/session_plan", data={"matchee_id": 2})
        self.assertEqual(result.status_code, 200)

        """Test planning a session (POST)"""
        result = self.client.post(
            "/session_plan",
            data={
                "machine1": "chest press",
                "machine2": "decline bench",
                "machine3": "incline bench",
                "machine4": "pectoral fly",
                "machine5": "ab roller",
            },
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

        """Test choosing member to JumpIn with"""
        result = self.client.post(
            "/propose_session",
            data={"matchee": "Member"},
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

        """Test choosing decision of accepting or declining"""
        result = self.client.post(
            "/complete_session",
            data={"username": "test", "decision": "accepted"},
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

    def test_chat_methods(self):
        """Test ability of user starting chat"""
        result = self.client.post(
            "/start_chat",
            data={
                "username": "test",
                "requester": "test",
                "room": "ABCD",
            },
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

        """Test ability of user joining chat"""
        result = self.client.post(
            "/join_chat",
            data={
                "username": "John Smith",
                "requestee": "test",
                "room": "ABCD",
            },
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

    def test_request_handling(self):
        """Test cancelling a session request"""
        result = self.client.post(
            "/cancel_request",
            data={"matchee_id": 7},
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

        """Test accepting a session request"""
        result = self.client.post(
            "/accept_request",
            data={"matcher": "John Smith", "matcher_id": 1},
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

        """Test declining a session request"""
        result = self.client.post(
            "/decline_request",
            data={"matcher": "John Smith", "matchee": "Jane Doe"},
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

    def test_chatroom_services(self):
        """Test room app.route"""
        self.app.config["LOGIN_DISABLED"] = True
        result = self.client.get(
            "/room/<room>",
            data={
                "room": "ABCD",
                "session['user_id']": "test",
                "rooms[room]": {"members": 0, "messages": []},
            },
            follow_redirects=True,
        )
        self.assertEqual(result.status_code, 200)

        """Test socket connect"""
        result

    def tearDown(self):
        """Test app shutdown"""
        self.app_ctxt.pop()
        self.app = None
        self.app_ctxt = None


if __name__ == "__main__":
    unittest.main()
