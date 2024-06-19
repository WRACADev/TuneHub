from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SubmitField
from wtforms.validators import DataRequired

class UploadAudioForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    file = FileField('Audio File', validators=[DataRequired()])
    submit = SubmitField('Upload')
