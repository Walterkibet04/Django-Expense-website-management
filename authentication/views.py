from django.shortcuts import render, redirect

from django.views import View
from django.contrib.auth.models import User
import json
from django.http import JsonResponse
from validate_email import validate_email 
from django.contrib import messages
from django.core.mail import send_mail
from django.contrib import auth
from django.urls import reverse
from django.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current-site
from .utils import token_generator


# Create your views here.
class EmailValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data['email']

        if not validate_email(email):
            return JsonResponse({'email_error': 'Please enter a valid email'}, status = 400)
        return JsonResponse({'email-valid': True})
    #    checks if email is taken
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'email is already in use choose another'}, status = 409)
        return JsonResponse({'email-valid': True})

class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data['username']

        if not str(username).isalnum():
            return JsonResponse({'username_error': 'username should only contain alphanumeric characters'}, status = 400)
        return JsonResponse({'username-valid': True})

        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'usernamealready in use'}, status = 409)
        return JsonResponse({'username-valid': True})

    
class RegistrationView(View):
    def get(self, request):
        return render(request, 'authentication/register.html')

    def post(self, request):
        # GET USER DATA
        # VALIDATE
        # create a user account

        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        context = {
            'fieldValues': request.POST
        }
        if not User.objects.filter(username=username).exists():
            if not User.objects.filter(email=email).exists():
                if len(password) < 6:
                    messages.error(request, 'Password too short')
                    return render(request, 'authentication/register.html', context)

                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.is_active = False
                user.save()

            # path to view
                # getting domain we are on
                #ralative url to verification
                # encode User ID
                # token
                uidb64 = force_bytes(urlsafe_base64_encode(user.pk))
                domain = get_current-site(request).domain
                link = reverse('activate',kwargs{'uidb64': uidb64 'token': token})

                email_subject = "Activate your account"
                email_body = ''
                send_mail(
                  email_subject,
                  email_body,
                    "noreply@semicolon.com",
                    [email],
                  fail_silently=False,
                )
                messages.success(request, 'Account created successfully')
                return render(request, 'authentication/register.html')

        return render(request, 'authentication/register.html')

class VerificationView(view):
    def get(self,request, uidb64, token):
       return redirect('login')
