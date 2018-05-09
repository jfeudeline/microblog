from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, Length

from app.models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    password2 = PasswordField(
        'confirmer le mot de passe',
        validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Valider')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError("Choisissez un autre nom d'utilisateur.")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("Choisissez une autre adresse email.")

class EditProfileForm(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[DataRequired()])
    about_me = TextAreaField("A propos de moi", validators=[Length(min=0, max=140)])
    submit = SubmitField('Valider')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError("Ce nom d'utilisateur est déjà utilisé !")

class PostForm(FlaskForm):
    post = TextAreaField('Message :', validators = [
        DataRequired(), Length(min=1, max=140)
    ])
    submit = SubmitField('Valider')