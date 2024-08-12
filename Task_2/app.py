import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Optional, ValidationError, Regexp
from flask_mysqldb import MySQL
import os
import re

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'database'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)

DEFAULT_AVATAR = 'default_avatar.jpg'


def validate_consecutive_numbers(phone_number):

    if re.search(r'(\d)\1{5,}', phone_number):  
        return False
    return True


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email already taken.')


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class ContactForm(FlaskForm):
    first_name = StringField("First Name", validators=[DataRequired()])
    second_name = StringField("Second Name", validators=[DataRequired()])
    phone_number = StringField("Phone Number", validators=[
        DataRequired(),
        Regexp(r'^\+([1-9]\d{1,14})$', message="Phone number must start with a country code and be valid.")
    ])
    email = StringField("Email", validators=[Optional(), Email()])
    submit = SubmitField("Save")

    def validate_phone_number(self, field):
        # Check if phone number is unique
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM contact WHERE phone_number=%s", (field.data,))
        existing_contact = cursor.fetchone()
        cursor.close()

        if existing_contact:
            raise ValidationError('Phone number already exists.')

        # Validate consecutive digits
        if not validate_consecutive_numbers(field.data):
            raise ValidationError('Phone number contains consecutive digits.')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                       (username, email, hashed_password.decode('utf-8')))
        mysql.connection.commit()
        cursor.close()
        flash("Registration successful! Please login.")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    session.pop('_flashes', None)

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            hashed_password = user[3].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                session['user_id'] = user[0]
                return redirect(url_for('contact'))
            else:
                flash("Wrong password. Please try again.", "error")
        else:
            flash("No account found with that email address.", "error")

    return render_template('login.html', form=form)


@app.route('/contact')
def contact():
    if 'user_id' not in session:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM contact WHERE user_id = %s", (user_id,))
    contacts = cursor.fetchall()
    cursor.close()

    return render_template('contact.html', contacts=contacts)


@app.route('/contact_details/<int:id>')
def contact_details(id):
    if 'user_id' not in session:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM contact WHERE id = %s AND user_id = %s", (id, user_id))
    contact = cursor.fetchone()
    cursor.close()

    if not contact:
        flash('Contact not found.')
        return redirect(url_for('contact'))

    return render_template('contact_details.html', contact=contact)


@app.route('/edit_contact/<int:id>', methods=['GET', 'POST'])
def edit_contact(id):
    if 'user_id' not in session:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM contact WHERE id = %s AND user_id = %s", (id, user_id))
    contact = cursor.fetchone()
    cursor.close()

    if not contact:
        flash('Contact not found.')
        return redirect(url_for('contact'))

    form = ContactForm(
        first_name=contact[1],
        second_name=contact[2],
        phone_number=contact[3],
        email=contact[4]
    )

    if form.validate_on_submit():
        first_name = form.first_name.data
        second_name = form.second_name.data
        phone_number = form.phone_number.data
        new_email = form.email.data

        avatar_filename = DEFAULT_AVATAR

        try:
            cursor = mysql.connection.cursor()
            cursor.execute(
                "UPDATE contact SET first_name = %s, second_name = %s, phone_number = %s, email = %s, avatar = %s WHERE id = %s AND user_id = %s",
                (first_name, second_name, phone_number, new_email, avatar_filename, id, user_id)
            )
            mysql.connection.commit()
            cursor.close()

            flash('Contact updated successfully!')
            return redirect(url_for('contact'))

        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error: {e}')
            print(f'Error: {e}')

    return render_template('edit_contact.html', form=form, contact=contact)


@app.route('/delete_contact/<int:id>', methods=['POST'])
def delete_contact(id):
    if 'user_id' not in session:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    user_id = session['user_id']

    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM contact WHERE id = %s AND user_id = %s", (id, user_id))
        mysql.connection.commit()
        cursor.close()

        flash('Contact deleted successfully!')
        return redirect(url_for('contact'))

    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error: {e}')
        print(f'Error: {e}')


@app.route('/add_contact', methods=['GET', 'POST'])
def add_contact():
    if 'user_id' not in session:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    form = ContactForm()
    if form.validate_on_submit():
        first_name = form.first_name.data
        second_name = form.second_name.data
        phone_number = form.phone_number.data
        email = form.email.data
        user_id = session['user_id']
        avatar_filename = DEFAULT_AVATAR

        try:
            cursor = mysql.connection.cursor()
            cursor.execute(
                "INSERT INTO contact (first_name, second_name, phone_number, email, avatar, user_id) VALUES (%s, %s, %s, %s, %s, %s)",
                (first_name, second_name, phone_number, email, avatar_filename, user_id)
            )
            mysql.connection.commit()
            cursor.close()

            flash('Contact added successfully!')
            return redirect(url_for('contact'))

        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error: {e}')
            print(f'Error: {e}')

    return render_template('add_contact.html', form=form)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/url_map')
def url_map():
    return str(app.url_map)


@app.route('/debug')
def debug():
    return f"Session content: {session}"


@app.route('/test_flash')
def test_flash():
    flash("This is a test flash message.")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
