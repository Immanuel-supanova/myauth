from typing import Any, Dict
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework import serializers,exceptions

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """This is a serializer for Users Model"""

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'username', 'is_active', 'date_joined']


class RegisterSerializer(UserSerializer):
    password = serializers.CharField(max_length=128, min_length=8, write_only=True, required=True)
    email = serializers.EmailField(required=True, write_only=True, max_length=128)

    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'is_active']

    def create(self, validated_data):
        try:
            user = User.objects.get(email=validated_data['email'])
        except ObjectDoesNotExist:
            user = User.objects.create_user(**validated_data)
        return user

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, write_only=True, max_length=128)
    domain = serializers.CharField(required=True, write_only=True, max_length=128)
    url = serializers.CharField(required=True, write_only=True, max_length=128)
    from_email = serializers.EmailField(required=True, write_only=True, max_length=128)

    def get_user(self,data):
        if "email" not in data:
            raise exceptions.ValidationError("email is required.")
        
        try:
            user = User.objects.get(email=data['email'])
        except ObjectDoesNotExist:
            raise exceptions.NotFound(self.error_messages["error"],"user does not exist.")
        
        if user.is_active == False:
            raise exceptions.NotFound(self.error_messages["error"],"user account has been deactivated.")
        
        return user
    
    def validate(self, data) -> Dict[Any, Any]:
        token = PasswordResetTokenGenerator()
        user = self.get_user(data=data)

        html_template = get_template("auth/email/password_reset_email.html")
        context = {
            'user': user, 
            'token': token.make_token(user=user), 
            'url':data["url"],
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'domain':data["domain"]
        }

        html_content = html_template.render(context)
        email = EmailMultiAlternatives(
            from_email=data["from_email"],
            subject="Reset Password",
            to=[data["email"]]
                  )
        email.attach_alternative(html_content, "text/html")
        email.send()
        
        return "An Email has been sent"
    

class PasswordResetConfirmSerializer(UserSerializer):
    new_password1 = serializers.CharField(required=True, write_only=True,)
    new_password2 = serializers.CharField(required=True, write_only=True,)
    uidb64 = serializers.CharField(required=True, write_only=True,)
    token = serializers.CharField(required=True, write_only=True,)

    class Meta:
        model = User
        fields = ['new_password1', 'new_password2', 'uidb64', 'token']
