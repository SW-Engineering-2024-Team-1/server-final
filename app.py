from flask import Flask, request, jsonify, session, send_from_directory
import os
import json
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_session import Session

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "mysql+pymysql://photo_user:1234@localhost/photo_diary"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "gif"}

# 세션 쿠키 설정
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(app.root_path, "flask_session")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
CORS(app, supports_credentials=True)
Session(app)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    keywords = db.Column(db.Text, nullable=False, default="[]")
    url = db.Column(db.String(200), nullable=False)

    @property
    def keywords_list(self):
        try:
            return json.loads(self.keywords)
        except (ValueError, TypeError):
            return []

    @keywords_list.setter
    def keywords_list(self, value):
        self.keywords = json.dumps(value)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    replyTo = db.relationship("Message", remote_side=[id], backref="replies")
    
    
@app.route("/")
def home():
    return "Hello, World!"



@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="pbkdf2:sha256")
    new_user = User(username=data["username"], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registered successfully"})


@app.route("/signin", methods=["POST"])
def signin():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify({"message": "Login failed"})
    session["user_id"] = user.id
    session["username"] = user.username
    return jsonify(
        {"message": "Login successful", "user_id": user.id, "username": user.username}
    )


@app.route("/signout", methods=["POST"])
def signout():
    session.pop("user_id", None)
    session.pop("username", None)
    return jsonify({"message": "Logged out successfully"})


@app.route("/check_session", methods=["GET"])
def check_session():
    if "user_id" in session:
        return jsonify(
            {
                "logged_in": True,
                "user_id": session["user_id"],
                "username": session["username"],
            }
        )
    else:
        return jsonify({"logged_in": False})


@app.route("/users", methods=["GET"])
def get_users():
    users = User.query.all()
    user_list = [{"id": user.id, "username": user.username} for user in users]
    return jsonify(user_list)


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    user_data = {
        "id": user.id,
        "username": user.username,
    }
    return jsonify(user_data)


@app.route("/photos", methods=["GET", "POST"])
def photos():
    if request.method == "GET":
        photos = Photo.query.all()
        if "user_id" in session:
            photo_list = [
                {
                    "id": photo.id,
                    "user_id": photo.user_id,
                    "description": photo.description,
                    "keywords": photo.keywords_list,
                    "url": f"/uploads/{photo.url}",
                }
                for photo in photos
            ]
        else:
            photo_list = []
        return jsonify(photo_list)
    if request.method == "POST":
        if "user_id" not in session:
            return jsonify({"message": "Unauthorized"}), 401
        data = request.form
        file = request.files["file"]
        filename = file.filename
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        keywords = json.loads(data.get("keywords", "[]"))
        new_photo = Photo(
            user_id=session["user_id"],
            description=data["description"],
            keywords=json.dumps(keywords),
            url=filename,
        )
        db.session.add(new_photo)
        db.session.commit()
        return jsonify({"message": "Photo uploaded successfully"})


@app.route("/upload_photo", methods=["POST"])
def upload_photo():
    if "user_id" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    user_id = session["user_id"]
    print(f"Uploading photo for user_id: {user_id}")  # 디버깅용 출력

    if "file" not in request.files:
        return jsonify({"message": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        data = request.form
        new_photo = Photo(
            user_id=user_id,
            description=data["description"],
            keywords=json.dumps(data.getlist("keywords[]")),
            url=filename,
        )
        db.session.add(new_photo)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")  # 디버깅용 출력
            return jsonify({"message": "Database error", "error": str(e)}), 500

        return jsonify({"message": "Photo uploaded successfully"})

    return jsonify({"message": "File type not allowed"}), 400


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/photos/<int:id>", methods=["GET", "PUT", "DELETE"])
def photo_detail(id):
    photo = Photo.query.get(id)
    if not photo:
        return jsonify({"message": "Photo not found"}), 404
    if request.method == "GET":
        photo_data = {
            "id": photo.id,
            "user_id": photo.user_id,
            "description": photo.description,
            "keywords": photo.keywords_list,
            "url": f"/uploads/{photo.url}",
        }
        return jsonify(photo_data)
    if request.method == "PUT":
        if photo.user_id != session.get("user_id"):
            return jsonify({"message": "Unauthorized"}), 401
        data = request.form
        photo.description = data["description"]
        photo.keywords_list = data.getlist("keywords[]")
        if "file" in request.files:
            file = request.files["file"]
            filename = file.filename
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            photo.url = filename
        db.session.commit()
        return jsonify({"message": "Photo updated successfully"})
    if request.method == "DELETE":
        if photo.user_id != session.get("user_id"):
            return jsonify({"message": "Unauthorized"}), 401
        db.session.delete(photo)
        db.session.commit()
        return jsonify({"message": "Photo deleted successfully"})


@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword")
    if not keyword:
        return jsonify({"message": "Keyword is required"}), 400

    photos = Photo.query.filter(Photo.keywords.contains(keyword)).all()
    photo_list = [
        {
            "id": photo.id,
            "user_id": photo.user_id,
            "description": photo.description,
            "keywords": json.loads(photo.keywords),
            "url": f"/uploads/{photo.url}",
        }
        for photo in photos
    ]
    return jsonify(photo_list)


@app.route("/messages", methods=["GET", "POST"])
def messages():
    if "user_id" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    if request.method == "GET":
        messages = Message.query.filter_by(receiver_id=session["user_id"]).all()
        message_list = [
            {
                "id": msg.id,
                "sender_id": msg.sender_id,
                "content": msg.content,
                "replyTo": {"id": msg.replyTo.id, "content": msg.replyTo.content}
                if msg.replyTo
                else None,
            }
            for msg in messages
        ]
        return jsonify(message_list)

    if request.method == "POST":
        data = request.get_json()
        new_message = Message(
            sender_id=session["user_id"],
            receiver_id=data["receiver_id"],
            content=data["content"],
            reply_to_id=data.get("reply_to_id"),
        )
        db.session.add(new_message)
        db.session.commit()
        return jsonify({"message": "Message sent successfully"})


@app.route("/messages/<int:id>", methods=["DELETE"])
def delete_message(id):
    message = Message.query.get(id)
    if not message:
        return jsonify({"message": "Message not found"}), 404
    if message.receiver_id != session.get("user_id"):
        return jsonify({"message": "Unauthorized"}), 401
    db.session.delete(message)
    db.session.commit()
    return jsonify({"message": "Message deleted successfully"})


@app.route("/messages/<int:receiver_id>", methods=["GET"])
def get_messages(receiver_id):
    if "user_id" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    sender_id = session["user_id"]
    messages = Message.query.filter(
        ((Message.sender_id == sender_id) & (Message.receiver_id == receiver_id))
        | ((Message.sender_id == receiver_id) & (Message.receiver_id == sender_id))
    ).all()

    message_list = [
        {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_username": User.query.get(msg.sender_id).username,
            "content": msg.content,
            "replyTo": {"id": msg.replyTo.id, "content": msg.replyTo.content}
            if msg.replyTo
            else None,
        }
        for msg in messages
    ]
    return jsonify(message_list)


@app.route("/profile", methods=["GET"])
def profile():
    if "user_id" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    user = User.query.get(session["user_id"])
    photos = Photo.query.filter_by(user_id=user.id).all()

    photo_list = [
        {
            "id": photo.id,
            "user_id": photo.user_id,
            "description": photo.description,
            "keywords": photo.keywords_list,
            "url": f"/uploads/{photo.url}",
        }
        for photo in photos
    ]

    user_data = {"id": user.id, "username": user.username}

    return jsonify({"user": user_data, "photos": photo_list})


@app.route("/photos/<int:id>", methods=["GET"])
def get_photo(id):
    photo = Photo.query.get(id)
    if not photo:
        return jsonify({"message": "Photo not found"}), 404

    photo_data = {
        "id": photo.id,
        "user_id": photo.user_id,
        "description": photo.description,
        "keywords": json.loads(photo.keywords),
        "url": f"/uploads/{photo.url}",
    }
    return jsonify(photo_data)


if __name__ == "__main__":
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])
    if not os.path.exists(app.config["SESSION_FILE_DIR"]):
        os.makedirs(app.config["SESSION_FILE_DIR"])
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    

