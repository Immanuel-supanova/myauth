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

from accounts.token import token_generator

User = get_user_model()


class RegisterForm(UserCreationForm):
    username = forms.CharField(label="Username", widget=forms.TextInput(attrs={"class": "form-control mx-auto w-75 "
                                                                               }))
    first_name = forms.CharField(label="Firstname", widget=forms.TextInput(attrs={"class": "form-control"
                                                                                  }))
    last_name = forms.CharField(label="Lastname", widget=forms.TextInput(attrs={"class": "form-control"
                                                                                }))

    email = forms.EmailField(label="Email", widget=forms.TextInput(attrs={"class": "form-control"
                                                                          }))

    password1 = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "class": "form-control"
                                          }),
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label="Password confirmation",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "class": "form-control"}),
        strip=False,
        help_text="Enter the same password as before, for verification.",
    )

    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email")

    def clean_username(self):
        username = self.cleaned_data.get('username')
        user_details = User.objects.filter(username=username)
        if user_details.exists():
            raise forms.ValidationError("Username is already taken")
        return username

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
    username = UsernameField(widget=forms.TextInput(attrs={"autofocus": True, "class": "form-control mx-auto w-75 "
                                                           }))
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "class": "form-control mx-auto w-75 "
                                          }),
    )


class UserPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        label="Old Password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={"autocomplete": "current-password", "autofocus": True, "class": "form-control mx-auto w-75 "
                   }),
    )
    new_password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "class": "form-control mx-auto w-75 "
                                          }),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    new_password2 = forms.CharField(
        label="New password confirmation",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "class": "form-control mx-auto w-75 "
                                          }),
    )


class UserPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(
        label="Email",
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "email", "class": "form-control mx-auto w-75"}),
    )


class UserChangeForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name')

        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control mx-auto w-75'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control mx-auto w-75'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control mx-auto w-75'}),
        }
