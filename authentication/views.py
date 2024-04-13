from django.shortcuts import render
from django.contrib.auth.models import User 
from django.views import View
import json
from django.http import JsonResponse
from validate_email import validate_email 
from django.contrib import messages

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
       #get user data
       #validate
       #create a user account

       username = request.POST['username']
       email = request.POST['email']
       password = request.POST['password']

       context={
        'fieldvalues': request.POST
       }

       if not User.objects.filter(username = username).exists():
            if not User.objects.filter(email = email).exists():

                if len(password)<6: 
                   messages.ERROR(request, 'password too short')
                   return render(request, 'authentication/register.html', context)
                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.save()
                messages.success(request, 'Account created successfully')
                return render(request, 'authentication/register.html')

       return render(request, 'authentication/register.html')