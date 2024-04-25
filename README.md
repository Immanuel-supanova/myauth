# myauth

This application mainly is for any kind of web project. It uses the django.contrib.auth as the authentication system. The repository contains one app called register which is for adding templates used for by django.contrib.auth

The app uses a custom user model.

Authentication using social apps is possible and can work with Python Social Auth

```commandline
pip install git+https://github.com/Immanuel-supanova/myauth.git
```

To set up the application the following settings should be implemented:

Settings.py

```
INSTALLED_APPS = [

    'django.contrib.sites',

    'accounts',
    'cyber',

    'rest_framework',
    "corsheaders",
]
```
```
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}
```
```
MIDDLEWARE = [
    
    "corsheaders.middleware.CorsMiddleware",
   
]
```
```
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
}
```
```
PRIVATE_KEY_FILE = f"{BASE_DIR}/private_key.pem"
PUBLIC_KEY_FILE = f"{BASE_DIR}/public_key.pem"
```
```
# Set the JWT cookie name and secure flag
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
JWT_AUTH_COOKIE = 'access_token'
JWT_AUTH_REFRESH_COOKIE = 'refresh_token'
```
```
SITE_ID = 1
```
```
CORS_ORIGIN_ALLOW_ALL = True
```
You can setup your own email backend here we are using mailgun so ensure you have mailgun account before continuing 
[mailgun](https://www.mailgun.com/) and use the crendentials you have been given to complete the following settings:
```
DEFAULT_FROM_EMAIL = '<sender-email-adress>'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.mailgun.org'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'mailgun-user-domain'
EMAIL_HOST_PASSWORD = 'mailgun-user-domain'
```
Change AUTH_USER_MODEL in order to tell django that the custom user model is the default user model

```
AUTH_USER_MODEL = 'accounts.User'
```
In the root urls.py file add the following paths:
```
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include

from cyber.views import AplicationTokenRefreshView, ApplicationTokenObtainPairView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('api/app/token/', ApplicationTokenObtainPairView.as_view()),
    path('api/app/token/refresh/', AplicationTokenRefreshView.as_view()),
    path('api/app/myauth/', include("accounts.api.application.urls"))

    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view()),
    path('api/myauth/', include("accounts.api.developer.urls")) 
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
```

In gitignore
```
private_key.pem
public_key.pem
```

run the following commands:
```commandline
python manage.py generate_keys
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
```
