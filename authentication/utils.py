from django.contrib.auth.tokens import PasswordResetTokenGenerate
from six import text_type

class AppTokenGenerator(PasswordResetTokenGenerate):

    def _make_hash_value(self, user, timestamp):
        return (text_type(user.is_active)+text_type(user.pk)+text_type(timestamp))

token_generator = AppTokenGenerator()