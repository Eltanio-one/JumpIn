from __future__ import annotations

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))


class User:
    """model for each individual user"""

    def __init__(
        self,
        username: str,
        email: str,
        name: str,
        date_of_birth: str,
        password: str,
        account_creation: str = None,
        hashed_password: str = None,
        languages: list = None,
        gym_id: int = None,
    ):
        self.username = username
        self.email = email
        self.name = name
        self.date_of_birth = date_of_birth
        self.password = password
        self.hashed_password = hashed_password
        self.languages = languages
        self.friends = []
        self.usage = {}
        self.gym_id = gym_id
        self.account_creation = account_creation


class UserService:
    """methods for user model"""

    def register_user(
        username: str,
        email: str,
        name: str,
        date_of_birth: str,
        password: str = None,
        hashed_password: str = None,
        languages: list = None,
        account_creation: str = None,
    ):
        new_user = User(
            username=username,
            email=email,
            name=name,
            date_of_birth=date_of_birth,
            password=password,
            languages=languages,
            account_creation=account_creation,
            hashed_password=hashed_password,
        )
        return new_user

    def add_friend(user: User, friend: User):
        user.friends.append(friend)

    def delete_friend(user: User, friend: User):
        user.friends.pop(friend)

    def add_usage(user: User, machine: str, amount: int):
        user.usage[machine] += amount

    def add_gym(user: User, gym_id: int):
        user.gym_id = gym_id

    def __repr__(user: User):
        return f"Name: {user.name}, Date of Birth: {user.date_of_birth}, Languages: {user.languages}"


class Gym:
    """model for each gym"""

    def __init__(
        self,
        username: str = None,
        address: str = None,
        email: str = None,
        account_creation: str = None,
        hashed_password: str = None,
    ):
        self.username = username
        self.address = address
        self.email = email
        self.opening_times = {
            "monday": "",
            "tuesday": "",
            "wednesday": "",
            "thursday": "",
            "friday": "",
            "saturday": "",
            "sunday": "",
        }
        self.account_creation = account_creation
        self.hashed_password = hashed_password
        self.machines = {}
        self.repairing = {}
        self.members = []


class GymService:
    """methods for each gym"""

    def register_gym(
        username: str = None,
        address: str = None,
        email: str = None,
        account_creation: str = None,
        hashed_password: str = None,
    ):
        new_gym = Gym(
            username=username,
            address=address,
            email=email,
            account_creation=account_creation,
            hashed_password=hashed_password,
        )
        return new_gym

    def add_times(
        gym: Gym,
        monday: str,
        tuesday: str,
        wednesday: str,
        thursday: str,
        friday: str,
        saturday: str,
        sunday: str,
    ):
        gym.opening_times["monday"] = monday
        gym.opening_times["tuesday"] = tuesday
        gym.opening_times["wednesday"] = wednesday
        gym.opening_times["thursday"] = thursday
        gym.opening_times["friday"] = friday
        gym.opening_times["saturday"] = saturday
        gym.opening_times["sunday"] = sunday

        return gym

    def add_member(gym: Gym, member: User):
        gym.members.append(member)
        return gym

    def remove_member(gym: Gym, member: User):
        gym.members.pop(member)
        return gym

    def add_machines(gym: Gym, machine: str, amount: int):
        if gym.machines.get(machine):
            gym.machines[machine] += amount
        else:
            gym.machines[machine] = amount
        return gym

    def remove_machines(gym: Gym, machine: str, amount: int):
        if gym.machines[machine] - amount >= 0:
            gym.machines[machine] -= amount
        else:
            gym.machines[machine] = 0
        return gym

    def add_to_repair(gym: Gym, machine: str, amount: int):
        if not gym.repairing.get(machine):
            gym.repairing[machine] = amount
        else:
            gym.repairing[machine] += amount
        return gym

    def __repr__(gym: Gym):
        return f"Name: {gym.name}, Address: {gym.address}, Opening Times: {gym.opening_times}"

