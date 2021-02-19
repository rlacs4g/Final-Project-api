from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(256), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    tos = db.Column(db.Boolean(), unique=False, nullable=False)
    is_active = db.Column(db.Boolean(), unique=False, nullable=False)
    diary = db.relationship('Food', backref = 'user')
    # Diary (relationship 1 to n -> Food)


    def repr(self):
        return '<User %r>' % self.username

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "first_name": self.firstname,
            "last_name": self.lastname

            # do not serialize the password, its a security breach
        }

    def validate(self,password):
        if not check_password_hash(self.password, password):
            return False

        return True

class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    calories = db.Column(db.String(50), nullable=False)
    serving_size = db.Column(db.String(120), unique=True, nullable=False)
    quantity = db.Column(db.String(80), unique=False, nullable=False)
    date = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    time_of_day = db.Column(db.Enum('morning','afternoon','night'), nullable=False, server_default='morning')

# Date (datetime stamp)
# Time of day (ENUM morning | afternoon | evening)
