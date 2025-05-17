from flask import Flask, render_template, request, url_for, session, redirect, flash
from flask_bootstrap import Bootstrap5
from flask_hashing import Hashing
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.utils import secure_filename
import os
from datetime import datetime


app = Flask(__name__)
app.config["SECRET_KEY"] = "secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///petbook.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
bootstrap = Bootstrap5(app)
hashing = Hashing(app)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)


# ----------------- DATABASE MODELS -----------------
class User(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)  # New field
    password_hash: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)

    profile: Mapped["Profile"] = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete")
    
class Profile(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'), unique=True)
    profile_pic: Mapped[str] = mapped_column(String(200), default="default.png")
    bio: Mapped[str] = mapped_column(Text, nullable=True)

    user: Mapped["User"] = db.relationship('User', back_populates='profile')

class Post(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    content: Mapped[str] = mapped_column(Text)
    image: Mapped[str] = mapped_column(String(200), nullable=True)  # <-- Add this line
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    user: Mapped["User"] = relationship("User")

class Comment(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    post_id: Mapped[int] = mapped_column(ForeignKey('post.id'))
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    content: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Message(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    receiver_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    content: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class CreateAdoptionPost(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    pet_name: Mapped[str] = mapped_column(String(100))
    breed: Mapped[str] = mapped_column(String(100))
    age: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text)
    image: Mapped[str] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="Available")

    user: Mapped["User"] = db.relationship('User')

class Notification(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    type: Mapped[str] = mapped_column(String(50))
    message: Mapped[str] = mapped_column(String(255))
    read_status: Mapped[str] = mapped_column(String(10), default='Unread')
    post_id: Mapped[int] = mapped_column(Integer, nullable=True)  # for adoption linking
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)  # <-- Add this

    user: Mapped["User"] = db.relationship('User')

class Friend(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user1_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    user2_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    status: Mapped[str] = mapped_column(String(50), default="Pending")

class Like(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    post_id: Mapped[int] = mapped_column(ForeignKey('post.id'))

class Log(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    action: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

# ----------------- ROUTES -----------------
@app.route('/')
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])
    if not user:
        session.clear()
        flash("Invalid session. Please log in again.", "warning")
        return redirect(url_for("login"))

    posts = Post.query.order_by(Post.timestamp.desc()).all()

    for post in posts:
        post.user = db.session.get(User, post.user_id)
        post.comments = Comment.query.filter_by(post_id=post.id).all()
        for comment in post.comments:
            comment.user = db.session.get(User, comment.user_id)
        post.likes = Like.query.filter_by(post_id=post.id).all()

    return render_template("user/home.html", username=user.username, posts=posts)# Redirect to login if the user is not logged in

@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        if name and username and password and email:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash("Username already exists. Please log in.", "danger")
                return redirect(url_for("login"))

            hashed_password = hashing.hash_value(password, salt="abcd")
            new_user = User(username=username, name=name, password_hash=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()

            new_profile = Profile(user_id=new_user.id, profile_pic="", bio="")
            db.session.add(new_profile)
            db.session.commit()
            
            session['user_id'] = new_user.id
            flash("Signup successful!", "success")
            return redirect(url_for("home"))
        
        flash("Please fill in all fields.", "danger")

    return render_template("authentication/signup.html")

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and hashing.check_value(user.password_hash, password, salt="abcd"):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('home'))


        flash('Invalid username or password.', 'danger')

    return render_template('authentication/login.html')

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return render_template("authentication/logout.html")

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'warning')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('home'))

    profile = user.profile

    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '':
                filename = secure_filename(file.filename)
                upload_path = os.path.join('static/uploads', filename)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                file.save(upload_path)
                profile.profile_pic = filename
                db.session.commit()
                flash("Profile picture updated!", "success")
                return redirect(url_for('profile'))

        # Handle name and bio update
        new_name = request.form.get('name')
        new_bio = request.form.get('bio')

        if new_name:
            user.name = new_name
        profile.bio = new_bio
        db.session.commit()
        flash("Profile updated!", "success")
        return redirect(url_for('profile'))

    return render_template('user/profile.html', user=user, profile=profile)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        flash("Please log in to create a post.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form['content']
        image_file = request.files['image']
        filename = None

        if image_file and image_file.filename != "":
            filename = secure_filename(image_file.filename)
            image_path = os.path.join('static/uploads', filename)
            image_file.save(image_path)

        new_post = Post(user_id=session['user_id'], content=content, image=filename)
        db.session.add(new_post)
        db.session.commit()

        flash("Post created!", "success")
        return redirect(url_for('home'))

    return render_template('user/create_post.html')

@app.route('/like/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        flash("Please log in to like posts.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()

    if not existing_like:
        new_like = Like(user_id=user_id, post_id=post_id)
        db.session.add(new_like)
        post = Post.query.get(post_id)
        if post and post.user_id != user_id:
            notif = Notification(
                user_id=post.user_id,
                type="Like",
                message=f"{User.query.get(user_id).username} liked your post."
            )
            db.session.add(notif)
        db.session.commit()
        flash("Post liked!", "success")
    else:
        flash("You already liked this post.", "info")

    return redirect(url_for('home'))

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment_post(post_id):
    if 'user_id' not in session:
        flash("Please log in to comment.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']  # <-- Add this line

    content = request.form.get('content')
    if not content:
        flash("Comment cannot be empty.", "danger")
        return redirect(url_for('home'))

    new_comment = Comment(user_id=user_id, post_id=post_id, content=content)
    db.session.add(new_comment)

    post = Post.query.get(post_id)
    if post and post.user_id != user_id:
        notif = Notification(
            user_id=post.user_id,
            type="Comment",
            message=f"{User.query.get(user_id).username} commented on your post."
        )
        db.session.add(notif)

    db.session.commit()
    flash("Comment added successfully!", "success")

    return redirect(url_for('home'))

@app.route('/adoption_listings')
def adoption_listing():
    posts = CreateAdoptionPost.query.filter_by(status="Available").all()
    return render_template('user/adoption_listing.html', posts=posts)


@app.route('/create_adoption_post', methods=['GET', 'POST'])
def create_adoption_post():
    if 'user_id' not in session:
        flash("Please log in to create an adoption post.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        pet_name = request.form['pet_name']
        breed = request.form['breed']
        age = request.form['age']
        description = request.form['description']
        image_file = request.files['image']
        filename = None

        if image_file and image_file.filename != "":
            filename = secure_filename(image_file.filename)
            image_path = os.path.join('static/uploads', filename)
            image_file.save(image_path)

        adoption_post = CreateAdoptionPost(
            user_id=session['user_id'],
            pet_name=pet_name,
            breed=breed,
            age=int(age),
            description=description,
            image=filename
        )
        db.session.add(adoption_post)
        db.session.commit()

        flash("Adoption post created!", "success")
        return redirect(url_for('adoption_listing'))

    return render_template('user/create_adoption_post.html')

@app.route('/adopt/<int:post_id>', methods=['POST'])
def adopt_pet(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    adoption_post = CreateAdoptionPost.query.get(post_id)
    if adoption_post and adoption_post.status == "Available":
        adoption_post.status = "Adopted"
        db.session.add(adoption_post)

        # Notify the owner
        if adoption_post.user_id != session['user_id']:
            notif = Notification(
                user_id=adoption_post.user_id,
                type="Adoption",
                message=f"{User.query.get(session['user_id']).username} wants to adopt {adoption_post.pet_name}!",
                post_id=post_id,
                read_status='Unread'
            )
            db.session.add(notif)

        db.session.commit()
        flash("Adoption request sent!", "success")
    else:
        flash("Pet is not available for adoption.", "danger")

    return redirect(url_for('adoption_listing'))

@app.route('/confirm_adoption/<int:post_id>', methods=['POST'])
def confirm_adoption(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    post = CreateAdoptionPost.query.get(post_id)

    if not post or post.user_id != session['user_id']:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('notification'))

    if post.status == 'Adopted':
        flash("This pet has already been adopted.", "warning")
        return redirect(url_for('notification'))

    # Retrieve latest adoption request from a different user
    adoption_request = Notification.query.filter(
        Notification.post_id == post_id,
        Notification.type == 'Adoption',
        Notification.user_id != session['user_id']
    ).order_by(Notification.id.desc()).first()

    if adoption_request:
        adopter_id = adoption_request.user_id

        # Send confirmation notification to adopter
        confirmation_note = Notification(
            user_id=adopter_id,
            type='Adoption Confirmation',
            message=f"Your adoption request for {post.pet_name} has been confirmed!",
            read_status='Unread',
            post_id=post_id
        )
        db.session.add(confirmation_note)

        post.status = 'Adopted'
        db.session.commit()

        flash("Adoption confirmed and notification sent to the adopter!", "success")
    else:
        flash("No adoption request found to confirm.", "danger")

    return redirect(url_for('notification'))


@app.route('/friends')
def friends():
    if 'user_id' not in session:
        flash("Please log in to view friends.", "warning")
        return redirect(url_for('login'))

    current_user_id = session['user_id']

    # Get all confirmed friendships involving the current user
    confirmed_friendships = Friend.query.filter(
        ((Friend.user1_id == current_user_id) | (Friend.user2_id == current_user_id)) &
        (Friend.status == "Accepted")
    ).all()

    # Get friend user objects
    friend_ids = [
        f.user2_id if f.user1_id == current_user_id else f.user1_id
        for f in confirmed_friendships
    ]
    current_friends = User.query.filter(User.id.in_(friend_ids)).all()

    # Get pending friend requests sent to current user
    pending_requests = Friend.query.filter_by(
        user2_id=current_user_id, status="Pending"
    ).all()
    request_senders = User.query.filter(User.id.in_([f.user1_id for f in pending_requests])).all()

    # Get users not yet friends or involved in a request
    all_user_ids = [u.id for u in User.query.all()]
    related_ids = set(friend_ids + [current_user_id] + [f.user1_id for f in pending_requests] +
                      [f.user2_id for f in Friend.query.filter_by(user1_id=current_user_id).all()])
    available_users = User.query.filter(User.id.notin_(related_ids)).all()

    return render_template('user/friends.html',
                           current_friends=current_friends,
                           request_senders=request_senders,
                           available_users=available_users)
    
@app.route('/send_friend_request/<int:user_id>')
def send_friend_request(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    new_request = Friend(user1_id=session['user_id'], user2_id=user_id, status='Pending')
    db.session.add(new_request)
    db.session.commit()
    flash("Friend request sent!", "info")
    return redirect(url_for('friends'))


@app.route('/accept_friend_request/<int:user_id>')
def accept_friend_request(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    request = Friend.query.filter_by(user1_id=user_id, user2_id=session['user_id'], status='Pending').first()
    if request:
        request.status = 'Accepted'
        db.session.commit()
        flash("Friend request accepted!", "success")
    return redirect(url_for('friends'))


@app.route('/delete_friend_request/<int:user_id>')
def delete_friend_request(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    request = Friend.query.filter_by(user1_id=user_id, user2_id=session['user_id'], status='Pending').first()
    if request:
        db.session.delete(request)
        db.session.commit()
        flash("Friend request declined.", "danger")
    return redirect(url_for('friends'))



@app.route('/messages')
def messages():
    return render_template('user/messages.html')

@app.route('/chat')
def chat():
    return render_template('user/chat.html')

@app.route('/notifications')
def notification():
    if 'user_id' not in session:
        flash("Please log in to view notifications.", "warning")
        return redirect(url_for('login'))

    notifications = Notification.query.filter_by(user_id=session['user_id']).order_by(Notification.id.desc()).all()
    return render_template('user/notification.html', notifications=notifications)

@app.route('/notifications/mark_read', methods=['POST'])
def mark_notifications_read():
    if 'user_id' not in session:
        return '', 401

    Notification.query.filter_by(user_id=session['user_id'], read_status='Unread').update({'read_status': 'Read'})
    db.session.commit()
    return '', 204

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash("You must be logged in to view settings.", "warning")
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Update fields
        user.name = name
        user.email = email
        user.username = username

        if password:  # Update password only if provided
            user.password_hash = hashing.hash_value(password)

        db.session.commit()
        flash("Your settings have been updated!", "success")
        return redirect(url_for('settings'))

    return render_template('user/settings.html', user=user)

# ----------------- RUN SERVER -----------------
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)