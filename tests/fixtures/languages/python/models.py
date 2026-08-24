class User:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email

    def __repr__(self):
        return f"User({self.name}, {self.email})"


class Database:
    def query_all(self, model_class):
        return []

    def query(self, model_class, id):
        return None

    def save(self, obj):
        pass

    def delete(self, obj):
        pass

    def search(self, model_class, query):
        return []


def legacy_format(data):
    return str(data)
