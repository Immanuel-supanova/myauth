from django.contrib.admin.models import LogEntry, CHANGE, DELETION
from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LogoutView
from django.contrib.contenttypes.models import ContentType
from django.http import HttpResponseRedirect
from django.shortcuts import render
# Create your views here.
from django.urls import reverse_lazy, reverse
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.views.generic import CreateView, UpdateView, DeleteView, RedirectView
from django.views.generic import TemplateView

from .forms import RegisterForm, UserChangeForm
from .token import token_generator

User = get_user_model()


class UserCreateView(CreateView):
    model = User
    form_class = RegisterForm
    template_name = "auth/signup.html"

    def form_valid(self, form):
        to_return = super().form_valid(form)

        user = form.save()
        user.is_active = False
        user.save()

        form.send_activation_email(self.request, user)

        return to_return

    def get_success_url(self, *args, **kwargs):  # use this to direct to its immediate detail view
        return reverse_lazy('check_email')


class UserUpdateView(LoginRequiredMixin, UpdateView):
    model = User
    form_class = UserChangeForm
    template_name = 'auth/user_change.html'

    def form_valid(self, form):
        profile = form.save(commit=False)
        profile.user = User.objects.get(id=self.request.user.id)
        LogEntry.objects.log_action(
            user_id=self.request.user.id,
            content_type_id=ContentType.objects.get_for_model(self.model).pk,
            object_id=self.object.id,
            object_repr=self.object.username,
            action_flag=CHANGE)
        profile.save()

        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        # ___________________________________________________________

        context = super().get_context_data(**kwargs)

        context['current_user'] = self.request.user.id
        return context

    def get_success_url(self):
        return reverse('logout')


class UserDeleteView(LoginRequiredMixin, DeleteView):
    template_name = 'auth/user_delete.html'
    model = User

    def form_valid(self, form):
        success_url = self.get_success_url()
        LogEntry.objects.log_action(
            user_id=self.request.user.id,
            content_type_id=ContentType.objects.get_for_model(self.model).pk,
            object_id=self.object.id,
            object_repr=self.object.username,
            action_flag=DELETION)
        self.object.delete()
        return HttpResponseRedirect(success_url)

    def get_context_data(self, **kwargs):
        # ___________________________________________________________

        context = super().get_context_data(**kwargs)

        context['current_user'] = self.request.user.id
        return context

    def get_success_url(self):
        return reverse('logout')


class SignoutView(LogoutView):
    def get_success_url(self):
        return reverse('login')


class ActivateView(RedirectView):
    url = reverse_lazy('success')

    # Custom get method
    def get(self, request, uidb64, token):

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)
            return super().get(request, uidb64, token)
        else:
            return render(request, 'auth/email/activate_account_invalid.html')


class CheckEmailView(TemplateView):
    template_name = 'auth/email/check_email.html'


class SuccessView(TemplateView):
    template_name = 'auth/email/success.html'


class IndexView(TemplateView):
    template_name = 'auth/index.html'

    def get_context_data(self, **kwargs):
        # ___________________________________________________________
        context = super().get_context_data(**kwargs)
        return context
