from django import forms
from django.conf import settings
from django.contrib.auth import password_validation, get_user_model
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, UsernameField, PasswordChangeForm, \
    PasswordResetForm
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .token import token_generator

User = get_user_model()


class RegisterForm(UserCreationForm):
    email = forms.EmailField(label="Email", widget=forms.TextInput(attrs={"class": "form-control",
                                                                          "placeholder": "Email Address",
                                                                          }))

    password1 = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "class": "form-control",
                                          "placeholder": "Password",
                                          }),
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label="Password confirmation",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "class": "form-control",
                                          "placeholder": "Confirm Password",
                                          }),
        strip=False,
        help_text="Enter the same password as before, for verification.",
    )

    class Meta:
        model = User
        fields = ("email",)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        user_details = User.objects.filter(email=email)
        if user_details.exists():
            raise forms.ValidationError("There is already an account with this email , please try logging in!")
        return email

    def send_activation_email(self, request, user):
        current_site = get_current_site(request)
        subject = 'Activate Your Account'
        message = render_to_string(
            'auth/email/activate_account.html',
            {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token_generator.make_token(user),
            }
        )

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [self.cleaned_data.get('email')],
                  html_message=message)


class LoginForm(AuthenticationForm):
    username = UsernameField(widget=forms.TextInput(attrs={"autofocus": True, "class": "form-control mx-auto w-75 ",
                                                           "placeholder": "Email Address",
                                                           }))
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "class": "form-control mx-auto w-75 ",
                                          "placeholder": "Password",
                                          }),
    )


class UserPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        label="Old Password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={"autocomplete": "current-password", "autofocus": True, "class": "form-control mx-auto w-75 ",
                   "placeholder": "Old Password",
                   }),
    )
    new_password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "class": "form-control mx-auto w-75 ",
                                          "placeholder": "New Password",

                                          }),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    new_password2 = forms.CharField(
        label="New password confirmation",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "class": "form-control mx-auto w-75 ",
                                          "placeholder": "New Password Confirmation",

                                          }),
    )


class UserPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(
        label="Email",
        max_length=254,
        widget=forms.EmailInput(
            attrs={"autocomplete": "email", "class": "form-control mx-auto w-75", "placeholder": "Email Address",
                   }),
    )


class UserChangeForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name')

        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control mx-auto w-75', "placeholder": "Username", }),
            'first_name': forms.TextInput(attrs={'class': 'form-control mx-auto w-75', "placeholder": "Firstname", }),
            'last_name': forms.TextInput(attrs={'class': 'form-control mx-auto w-75', "placeholder": "Lastname", }),
        }

    def clean_username(self):
        username = self.cleaned_data.get('username')
        user_details = User.objects.filter(username=username)
        if user_details.exists():
            raise forms.ValidationError("Username is already taken")
        return username
