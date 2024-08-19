from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf import FlaskForm
from flask import send_from_directory
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, DateTimeField
from wtforms.validators import DataRequired, Email, Optional
from flask_mysqldb import MySQL
import bcrypt
import jwt
from flask_wtf.file import FileField, FileAllowed
from functools import wraps
import smtplib
from email.mime.text import MIMEText
import os
from werkzeug.utils import secure_filename
from flask import render_template, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__, static_folder='static')
app.config['UPLOAD_FOLDER'] = 'static/uploads'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'events'
app.config['SECRET_KEY'] = 'your_secret_key_here'

mysql = MySQL(app)

JWT_SECRET = 'your_jwt_secret'


def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing.'}), 401
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except Exception as e:
            return jsonify({'success': False, 'message': 'Token is invalid.'}), 401
        return f(*args, **kwargs)

    return decorated_function


class Registration(FlaskForm):
    first_name = StringField("First name", validators=[DataRequired()])
    last_name = StringField("Last name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class Login(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class ShareEventForm(FlaskForm):
    email = StringField("Friend's Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Share")


class Events(FlaskForm):
    Event_type = SelectField("Event type",
                             choices=[('concert', 'Concert'), ('party', 'Party'), ('festival', 'Festival'),
                                      ('sports', 'Sports')],
                             validators=[DataRequired()])
    Event_name = StringField("Name", validators=[Optional()])
    Event_location = StringField("Location", validators=[Optional()])
    Event_time = DateTimeField("Time", format='%Y-%m-%d %H:%M:%S', validators=[Optional()])
    additional_info = TextAreaField("Additional Information", validators=[Optional()])

    # Conditional fields
    singer_name = StringField("Singer Name", validators=[Optional()])
    party_place = StringField("Place", validators=[Optional()])
    party_type = StringField("Type of Party", validators=[Optional()])
    dresscode = StringField("Dresscode", validators=[Optional()])
    facilities = TextAreaField("Facilities", validators=[Optional()])
    festival_name = StringField("Festival Name", validators=[Optional()])
    festival_type = StringField("Festival Type", validators=[Optional()])
    festival_purpose = TextAreaField("Purpose", validators=[Optional()])
    sport_type = StringField("Type of Sport", validators=[Optional()])
    teams_involved = StringField("Teams Involved", validators=[Optional()])
    event_image = FileField('Event Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])


class CommentForm(FlaskForm):
    comment_text = TextAreaField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit")


class ShareEventForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registration()
    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        cursor.execute(
            'INSERT INTO users (first_name, last_name, username, email, password) VALUES (%s, %s, %s, %s, %s)',
            (first_name, last_name, username, email, hashed_password)
        )
        mysql.connection.commit()
        cursor.close()
        flash("Successful Registration!! Please Login.")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            hashed_password = user[5]
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                session['user_id'] = user[0]
                return redirect(url_for('home'))
            else:
                flash("Wrong password. Please try again.", "error")
        else:
            flash("No account found with that email address.", "error")

    return render_template('login.html', form=form)


@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/event/create', methods=['GET', 'POST'])
def create_event():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = Events()
    if form.validate_on_submit():
        event_name = form.Event_name.data
        event_location = form.Event_location.data
        event_time = form.Event_time.data
        event_type = form.Event_type.data
        additional_info = form.additional_info.data
        user_id = session.get('user_id')

        event_image = form.event_image.data
        if event_image:
            filename = secure_filename(event_image.filename)
            image_path = os.path.join(filename)
            event_image.save(image_path)
        else:
            image_path = None

        cursor = mysql.connection.cursor()
        try:
            if event_type == 'concert':
                singer_name = form.singer_name.data
                cursor.execute("""
                    INSERT INTO events (event_name, event_location, event_time, event_type, additional_info, singer_name
                    , 
                    event_image, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (event_name, event_location, event_time, event_type, additional_info, singer_name, image_path,
                      user_id))
            elif event_type == 'party':
                party_place = form.party_place.data
                party_type = form.party_type.data
                dresscode = form.dresscode.data
                cursor.execute("""
                    INSERT INTO events (event_name, event_location, event_time, event_type, additional_info, party_place
                    , party_type, dresscode, event_image, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (event_name, event_location, event_time, event_type, additional_info, party_place, party_type,
                      dresscode, image_path, user_id))
            elif event_type == 'festival':
                festival_name = form.festival_name.data
                festival_type = form.festival_type.data
                festival_purpose = form.festival_purpose.data
                cursor.execute("""
                    INSERT INTO events (event_name, event_location, event_time, event_type, additional_info, 
                    festival_name, festival_type, festival_purpose, event_image, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (event_name, event_location, event_time, event_type, additional_info, festival_name, festival_type,
                      festival_purpose, image_path, user_id))
            elif event_type == 'sports':
                sport_type = form.sport_type.data
                teams_involved = form.teams_involved.data
                cursor.execute("""
                    INSERT INTO events (event_name, event_location, event_time, event_type, additional_info, sport_type,
                     teams_involved, event_image, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (event_name, event_location, event_time, event_type, additional_info, sport_type, teams_involved,
                      image_path, user_id))
            else:
                cursor.execute("""
                    INSERT INTO events (event_name, event_location, event_time, event_type, additional_info, event_image
                    , user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (event_name, event_location, event_time, event_type, additional_info, image_path, user_id))

            mysql.connection.commit()
            cursor.close()
            return redirect(url_for('events'))
        except Exception as e:
            print(f"Error: {e}")
            mysql.connection.rollback()
            return jsonify({'success': False, 'message': 'An error occurred while creating the event.'}), 500

    return render_template('create_event.html', form=form)


@app.route('/events', methods=['GET'])
def events():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'event_time')
    filter_category = request.args.get('category', 'all')

    query = """
        SELECT * FROM events
        WHERE event_name LIKE %s
    """
    filters = ['%' + search_query + '%']

    if filter_category != 'all':
        query += " AND event_type = %s"
        filters.append(filter_category)

    query += f" ORDER BY {sort_by}"

    cursor = mysql.connection.cursor()
    cursor.execute(query, tuple(filters))
    events = cursor.fetchall()
    cursor.close()

    user_id = session.get('user_id')
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT event_id, rsvp_status
        FROM attendees
        WHERE user_id = %s
    """, (user_id,))
    user_rsvps = {row[0]: row[1] for row in cursor.fetchall()}
    cursor.close()

    return render_template('events.html', events=events, user_rsvps=user_rsvps)


@app.route('/event/edit/<int:event_id>', methods=['GET', 'POST'])
def edit_event(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = Events()
    if form.validate_on_submit():
        event_name = form.Event_name.data
        event_location = form.Event_location.data
        event_time = form.Event_time.data
        event_type = form.Event_type.data
        additional_info = form.additional_info.data
        user_id = session.get('user_id')

        cursor = mysql.connection.cursor()
        try:
            if event_type == 'concert':
                singer_name = form.singer_name.data
                cursor.execute("""
                    UPDATE events
                    SET event_name = %s, event_location = %s, event_time = %s, event_type = %s, additional_info = %s, 
                    singer_name = %s
                    WHERE id = %s AND user_id = %s
                """, (event_name, event_location, event_time, event_type, additional_info, singer_name, event_id,
                      user_id))
            elif event_type == 'party':
                party_place = form.party_place.data
                party_type = form.party_type.data
                dresscode = form.dresscode.data
                cursor.execute("""
                    UPDATE events
                    SET event_name = %s, event_location = %s, event_time = %s, event_type = %s, additional_info = %s, 
                    party_place = %s, party_type = %s, dresscode = %s
                    WHERE id = %s AND user_id = %s
                """, (event_name, event_location, event_time, event_type, additional_info, party_place, party_type,
                      dresscode, event_id, user_id))
            elif event_type == 'festival':
                festival_name = form.festival_name.data
                festival_type = form.festival_type.data
                festival_purpose = form.festival_purpose.data
                cursor.execute("""
                    UPDATE events
                    SET event_name = %s, event_location = %s, event_time = %s, event_type = %s, additional_info = %s, 
                    festival_name = %s, festival_type = %s, festival_purpose = %s
                    WHERE id = %s AND user_id = %s
                """, (event_name, event_location, event_time, event_type, additional_info, festival_name, festival_type,
                      festival_purpose, event_id, user_id))
            elif event_type == 'sports':
                sport_type = form.sport_type.data
                teams_involved = form.teams_involved.data
                cursor.execute("""
                    UPDATE events
                    SET event_name = %s, event_location = %s, event_time = %s, event_type = %s, additional_info = %s, 
                    sport_type = %s, teams_involved = %s
                    WHERE id = %s AND user_id = %s
                """, (event_name, event_location, event_time, event_type, additional_info, sport_type, teams_involved,
                      event_id, user_id))
            else:
                cursor.execute("""
                    UPDATE events
                    SET event_name = %s, event_location = %s, event_time = %s, event_type = %s, additional_info = %s
                    WHERE id = %s AND user_id = %s
                """, (event_name, event_location, event_time, event_type, additional_info, event_id, user_id))

            mysql.connection.commit()
            cursor.close()
            flash("Event updated successfully.", "success")
            return redirect(url_for('events'))
        except Exception as e:
            print(f"Error: {e}")
            mysql.connection.rollback()
            return jsonify({'success': False, 'message': 'An error occurred while updating the event.'}), 500

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM events WHERE id = %s AND user_id = %s", (event_id, session.get('user_id')))
    event = cursor.fetchone()
    cursor.close()

    if event:
        form.Event_name.data = event[1]
        form.Event_location.data = event[2]
        form.Event_time.data = event[3]
        form.Event_type.data = event[4]
        form.additional_info.data = event[5]
        if event[4] == 'concert':
            form.singer_name.data = event[6]
        elif event[4] == 'party':
            form.party_place.data = event[7]
            form.party_type.data = event[8]
            form.dresscode.data = event[9]
        elif event[4] == 'festival':
            form.festival_name.data = event[10]
            form.festival_type.data = event[11]
            form.festival_purpose.data = event[12]
        elif event[4] == 'sports':
            form.sport_type.data = event[13]
            form.teams_involved.data = event[14]
    else:
        flash("Event not found or you don't have permission to edit this event.", "error")
        return redirect(url_for('events'))

    return render_template('edit_event.html', form=form, event_id=event_id)


@app.route('/event/delete/<int:event_id>', methods=['POST'])
def delete_event(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM events WHERE id = %s AND user_id = %s", (event_id, session.get('user_id')))
    mysql.connection.commit()
    cursor.close()
    flash("Event deleted successfully.", "success")
    return redirect(url_for('events'))


@app.route('/event/rsvp/<int:event_id>', methods=['POST'])
def rsvp(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    status = request.form.get('status')

    cursor = mysql.connection.cursor()
    cursor.execute("""
        INSERT INTO attendees (event_id, user_id, rsvp_status)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE rsvp_status = %s
    """, (event_id, user_id, status, status))
    mysql.connection.commit()
    cursor.close()

    flash("Your RSVP has been updated.", "success")
    return redirect(url_for('events'))


@app.route('/event/attendees/<int:event_id>')
def event_attendees(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT u.username, a.rsvp_status
        FROM attendees a
        JOIN users u ON a.user_id = u.id
        WHERE a.event_id = %s
    """, (event_id,))
    attendees = cursor.fetchall()
    cursor.close()

    return render_template('event_attendees.html', attendees=attendees, event_id=event_id)


@app.route('/send_reminders/<int:event_id>')
def send_reminders(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT u.email, e.event_name, e.event_time
        FROM attendees a
        JOIN users u ON a.user_id = u.id
        JOIN events e ON a.event_id = e.id
        WHERE a.event_id = %s AND a.rsvp_status = 'confirmed'
    """, (event_id,))
    attendees = cursor.fetchall()
    cursor.close()

    for attendee in attendees:
        email = attendee[0]
        event_name = attendee[1]
        event_time = attendee[2].strftime('%Y-%m-%d %H:%M:%S')

        subject = f"Reminder: {event_name} is happening soon!"
        body = (f"Hi there,\n\nThis is a reminder that the event '{event_name}' is scheduled to occur on {event_time}"
                f". We look forward to seeing you there!\n\nBest regards,\nEvent Team")
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'noreply@yourdomain.com'
        msg['To'] = email

        try:
            with smtplib.SMTP('smtp.yourdomain.com', 587) as server:
                server.starttls()
                server.login('your_email@yourdomain.com', 'your_email_password')
                server.sendmail('noreply@yourdomain.com', email, msg.as_string())
        except Exception as e:
            print(f"Failed to send email to {email}: {e}")

    flash("Reminders have been sent successfully.", "success")
    return redirect(url_for('event_attendees', event_id=event_id))


@app.route('/search', methods=['GET'])
def search_events():
    search_query = request.args.get('query', '')
    category = request.args.get('category', '')
    date = request.args.get('date', '')

    query = "SELECT * FROM events WHERE event_name LIKE %s"
    filters = ['%' + search_query + '%']

    if category:
        query += " AND event_type = %s"
        filters.append(category)
    if date:
        query += " AND DATE(event_time) = %s"
        filters.append(date)

    cursor = mysql.connection.cursor()
    cursor.execute(query, tuple(filters))
    events = cursor.fetchall()
    cursor.close()

    return jsonify(events)


@app.route('/event/<int:event_id>/comment', methods=['POST'])
def add_comment(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = CommentForm()
    if form.validate_on_submit():
        comment_text = form.comment_text.data
        user_id = session.get('user_id')

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO comments (event_id, user_id, comment_text)
            VALUES (%s, %s, %s)
        """, (event_id, user_id, comment_text))
        mysql.connection.commit()
        cursor.close()

        flash("Comment added successfully.", "success")
    else:
        flash("Comment could not be added. Please try again.", "error")

    return redirect(url_for('event_details', event_id=event_id))


@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    cursor.execute("""
        SELECT e.*
        FROM events e
        JOIN shares s ON e.id = s.event_id
        WHERE s.user_id = %s
    """, (user_id,))
    shared_events = cursor.fetchall()

    cursor.close()

    return render_template('profile.html', user=user, shared_events=shared_events)


@app.route('/event/<int:event_id>/comments')
def view_comments(event_id):
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT c.comment_text, u.username, c.created_at
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.event_id = %s
    """, (event_id,))
    comments = cursor.fetchall()
    cursor.close()

    return render_template('comments.html', comments=comments, event_id=event_id)


@app.route('/event/<int:event_id>/share', methods=['POST'])
def share_event(event_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    email = request.form.get('email')

    cursor = mysql.connection.cursor()
    cursor.execute("""
        INSERT INTO shares (event_id, user_id, shared_with_email)
        VALUES (%s, %s, %s)
    """, (event_id, user_id, email))
    mysql.connection.commit()
    cursor.close()

    flash("Event shared successfully.", "success")
    return redirect(url_for('profile', user_id=user_id))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/event/<int:event_id>')
def event_details(event_id):
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT * FROM events WHERE id = %s
    """, (event_id,))
    event = cursor.fetchone()

    if event:
        cursor.execute("""
            SELECT c.comment_text, u.username, c.created_at
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.event_id = %s
        """, (event_id,))
        comments = cursor.fetchall()
        cursor.close()

        form = CommentForm()
        return render_template('event_details.html', event=event, comments=comments, form=form)
    else:
        flash("Event not found.", "error")
        return redirect(url_for('events'))


def get_current_user_id():
    return current_user.id


if __name__ == "__main__":
    app.run(debug=True)
