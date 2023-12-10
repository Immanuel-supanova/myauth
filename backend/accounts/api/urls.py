from django.urls import path

from .views import UserList, UserRetrieve, UserCreate ,CurrentUser

urlpatterns = [
    path('users/create/', UserCreate.as_view()),
    path('users/', UserList.as_view()),
    path('users/<int:pk>/', UserRetrieve.as_view()),
    path('current-users/', CurrentUser.as_view()),

]
