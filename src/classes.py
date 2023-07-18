from __future__ import annotations


class Machine:
    """class for machines when gyms adding to repertoire"""

    def __init__(self, name: str, supplier: str):
        self.name = name
        self.supplier = supplier


class User:
    """class for each individual user"""

    def __init__(
        self,
        username: str,
        email: str,
        name: str,
        date_of_birth: str,
        password: str,
        languages: list,
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

    def add_friend(self, friend: User):
        self.friends.append(friend)

    def delete_friend(self, friend: User):
        self.friends.pop(friend)

    def add_usage(self, machine: Machine, amount: int):
        self.usage[machine] += amount

    def __repr__(self):
        return f"Name: {self.name}, Date of Birth: {self.date_of_birth}, Languages: {self.languages}"


class Gym:
    """class for a gym when setting up an account"""

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

    def add_times(
        self,
        monday: str,
        tuesday: str,
        wednesday: str,
        thursday: str,
        friday: str,
        saturday: str,
        sunday: str,
    ):
        self.opening_times["Monday"] = monday
        self.opening_times["Tuesday"] = tuesday
        self.opening_times["Wednesday"] = wednesday
        self.opening_times["Thursday"] = thursday
        self.opening_times["Friday"] = friday
        self.opening_times["Saturday"] = saturday
        self.opening_times["Sunday and Bank Holidays"] = sunday

    def add_machines(self, machine: Machine, amount: int):
        self.machines[machine] = amount

    def remove_machines(self, machine: Machine, amount: int):
        self.machines[machine] = self.machines[machine] - amount

    def add_to_repair(self, machine: Machine, amount: int):
        self.machines[machine] = self.machines[machine] - amount
        self.repairing[machine] = amount

    def __repr__(self):
        return f"Name: {self.name}, Address: {self.address}, Opening Times: {self.opening_times}"


class Sesh:
    """Detials for each session successfully completed"""

    def __init__(
        self, members: list, machines: list, booking_date: str, session_date: str
    ):
        self.members = members
        self.machines = machines
        self.booking_date = booking_date
        self.session_date = session_date
