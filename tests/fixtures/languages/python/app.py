import os

from flask import Flask, jsonify, request
from models import Database, User
from utils import format_response, validate_email

app = Flask(__name__)
db = Database()


@app.route("/users", methods=["GET"])
def get_users():
    users = db.query_all(User)
    return jsonify(format_response(users))


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = db.query(User, user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(format_response(user))


@app.route("/users", methods=["POST"])
def create_user():
    data = request.get_json()
    if not validate_email(data["email"]):
        return jsonify({"error": "Invalid email"}), 400
    user = User(name=data["name"], email=data["email"])
    db.save(user)
    return jsonify(format_response(user)), 201


@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    data = request.get_json()
    user = db.query(User, user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    user.name = data.get("name", user.name)
    user.email = data.get("email", user.email)
    db.save(user)
    return jsonify(format_response(user))


@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    user = db.query(User, user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    db.delete(user)
    return jsonify({"message": "Deleted"}), 200


@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]
    path = os.path.join("/uploads", file.filename)
    file.save(path)
    return jsonify({"path": path})


@app.route("/search")
def search():
    query = request.args.get("q", "")
    results = db.search(User, query)
    return jsonify(format_response(results))


def unused_helper():
    pass


def another_unused(x, y):
    return x + y


if __name__ == "__main__":
    app.run(debug=True)
