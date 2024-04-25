from django.contrib.auth import get_user_model
from rest_framework import generics, status
from rest_framework import exceptions

from django.contrib.admin.models import LogEntry, CHANGE
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ValidationError
from rest_framework.response import Response
from accounts.api.serializers import PasswordResetSerializer, RegisterSerializer, UserSerializer, PasswordResetConfirmSerializer
from cyber.auth import ApplicationAuthentication
from cyber.models import Application
from cyber.permissions import ApplicationRequiredPermissions
from django.utils.http import urlsafe_base64_decode

User = get_user_model()

# Application 
class AppUserCreate(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    queryset = User.objects.all()
    authentication_classes = (ApplicationAuthentication,)
    permission_classes = (ApplicationRequiredPermissions,)


class AppUserList(generics.ListAPIView):
    """
    UserList lists all User entities
    """

    serializer_class = UserSerializer
    queryset = User.objects.exclude(is_superuser=True)
    authentication_classes = (ApplicationAuthentication,)
    permission_classes = (ApplicationRequiredPermissions,)


class AppUserRetrieve(generics.RetrieveAPIView):
    """
    UserRetrieve is used to retrieve individual users from the database
    """

    serializer_class = UserSerializer
    queryset = User.objects.exclude(is_superuser=True)
    authentication_classes = (ApplicationAuthentication,)
    permission_classes = (ApplicationRequiredPermissions,)


class AppUserPasswordReset(generics.GenericAPIView):
    authentication_classes = (ApplicationAuthentication,)
    serializer_class = PasswordResetSerializer

    def check_permissions(self, request):
        token = request.auth

        if not token:
            return False
        
        uuid = token["uuid"]
        app = Application.objects.get(uuid=uuid)
        if not app:
            return False

        u = app.user_permissions.get_by_natural_key("request_user_password_reset_token", "accounts", "user")
        if not u:
            return False
        
        return True

    def post(self, request, *args, **kwargs):
        # Accessing data from POST request
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            raise ValidationError(e.args[0])
        
        return Response({"message": serializer.validated_data}, status=status.HTTP_200_OK)

class AppUserPasswordResetConfirm(generics.UpdateAPIView):
    serializer_class = PasswordResetConfirmSerializer
    queryset = User.objects.all()
    authentication_classes = (ApplicationAuthentication,)
    permission_classes = (ApplicationRequiredPermissions,)


    def get_object(self, request):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uidb64 = request.data["uidb64"]
        id = urlsafe_base64_decode(uidb64).decode()

        obj = User.objects.get(id=id)

        return obj
    
    def update(self, request, *args, **kwargs):
        token = PasswordResetTokenGenerator()

        password1 = request.data["new_password1"]
        password2 = request.data["new_password2"]

        if password1 and password2 and password1 != password2:
            raise exceptions.ValidationError(
                "password_mismatch",
            )
        
        partial = kwargs.pop('partial', False)
        instance = self.get_object(request)
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        if token.check_token(instance, request.data["token"]) == False:
            raise exceptions.ValidationError("token is invalid")
        
        instance.set_password(password1)
        instance.save()
        LogEntry.objects.log_action(
            user_id=instance.pk,
            content_type_id=ContentType.objects.get_for_model(instance).pk,
            object_id=instance.pk,
            object_repr=instance.username,
            action_flag=CHANGE)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        data = {"Message": "Password reset confirmed"}

        return Response(data)