from __future__ import annotations


class Machine:
    """model for machines"""

    def __init__(self, name: str, supplier: str):
        self.name = name
        self.supplier = supplier


class User:
    """model for each individual user"""

    def __init__(
        self,
        username: str,
        email: str,
        name: str,
        date_of_birth: str,
        password: str,
        languages: list,
        gym: Gym = None,
    ):
        self.username = username
        self.email = email
        self.name = name
        self.date_of_birth = date_of_birth
        self.password = password
        self.hashed_password = None
        self.languages = languages
        self.friends = []
        self.usage = {}
        self.gym = gym


class UserService:
    """methods for user model"""

    def register_user(
        username: str,
        email: str,
        name: str,
        date_of_birth: str,
        password: str,
        languages: list,
    ):
        new_user = User(
            username=username,
            email=email,
            name=name,
            date_of_birth=date_of_birth,
            password=password,
            languages=languages,
        )
        return new_user

    def add_friend(user: User, friend: User):
        user.friends.append(friend)

    def delete_friend(user: User, friend: User):
        user.friends.pop(friend)

    def add_usage(user: User, machine: Machine, amount: int):
        user.usage[machine] += amount

    def add_gym(user: User, gym: Gym):
        user.gym = gym

    def __repr__(user: User):
        return f"Name: {user.name}, Date of Birth: {user.date_of_birth}, Languages: {user.languages}"


class Gym:
    """model for each gym"""

    def __init__(self, name: str, address: str):
        self.name = name
        self.address = address
        self.opening_times = {
            "Monday": "",
            "Tuesday": "",
            "Wednesday": "",
            "Thursday": "",
            "Friday": "",
            "Saturday": "",
            "Sunday and Bank Holidays": "",
        }
        self.machines = {}
        self.reparing = {}
        self.members = []


class GymService:
    """methods for each gym"""

    def register_gym(name: str, address: str):
        new_gym = Gym(name=name, address=address)
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
        gym.opening_times["Monday"] = monday
        gym.opening_times["Tuesday"] = tuesday
        gym.opening_times["Wednesday"] = wednesday
        gym.opening_times["Thursday"] = thursday
        gym.opening_times["Friday"] = friday
        gym.opening_times["Saturday"] = saturday
        gym.opening_times["Sunday and Bank Holidays"] = sunday

    def add_member(gym: Gym, member: User):
        gym.members.append(member)

    def remove_member(gym: Gym, member: User):
        gym.members.pop(member)

    def add_machines(gym: Gym, machine: Machine, amount: int):
        gym.machines[machine] = amount

    def remove_machines(gym: Gym, machine: Machine, amount: int):
        gym.machines[machine] = gym.machines[machine] - amount

    def add_to_repair(gym: Gym, machine: Machine, amount: int):
        gym.machines[machine] = gym.machines[machine] - amount
        gym.repairing[machine] = amount

    def __repr__(gym: Gym):
        return f"Name: {gym.name}, Address: {gym.address}, Opening Times: {gym.opening_times}"


class Sesh:
    """Detials for each session successfully completed"""

    def __init__(
        self, members: list, machines: list, booking_date: str, session_date: str
    ):
        self.members = members
        self.machines = machines
        self.booking_date = booking_date
        self.session_date = session_date
