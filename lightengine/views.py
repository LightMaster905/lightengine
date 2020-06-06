from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.template import loader
from django.urls import reverse
from django.shortcuts import render, get_object_or_404
from django.views import generic
from django.utils import timezone
from docs.models import User

def get_ip(request):
    return request.META["REMOTE_ADDR"]

def get_user(ip):
    for user in User.objects.all():
        if user.logged_in_as == "0":
            continue
        else:
            if user.logged_in_as == ip:
                return user
    return "logged_out"

def index(request):
    user = get_user(ip=get_ip(request))

    if user != "logged_out":
        return render(request, 'main/index.html', {
            "theme": user.theme,
            "username": user.username,
            "request": request,
        })
    else:
        return render(request, 'main/index.html',{
            "theme": "light",
            "request": request,
        })

def user_setings_view(request):
    user = get_user(ip=get_ip(request))

    try:
        last_page = request.POST["path"]
        if user != "logged_out":
            return render(request, 'main/user_settings.html', {
                "theme": user.theme,
                "username": user.username,
                "request": request,
                "last_page": last_page,
            })
        else:
            return render(request, 'main/user_settings.html',{
                "theme": "light",
                "request": request,
                "last_page": last_page,
            })
    except:
        if user != "logged_out":
            return render(request, 'main/user_settings.html', {
                "theme": user.theme,
                "username": user.username,
                "request": request,
            })
        else:
            return render(request, 'main/user_settings.html',{
                "theme": "light",
                "request": request,
            })

def login_view(request):
    user = get_user(ip=get_ip(request))

    if user != "logged_out":
        return render(request, 'main/login.html', {
            "username": user.username,
            "theme": user.theme,
            "request": request,
        })
    else:
        return render(request, 'main/login.html',{
            "request": request,
            "theme": "light",
        })

def sign_up_view(request):
    user = get_user(ip=get_ip(request))

    if user != "logged_out":
        return render(request, 'main/sign_up.html',{
            "username": user.username,
            "theme": user.theme,
            "request": request,
        })
    else:
        return render(request, 'main/sign_up.html',{
            "request": request,
            "theme": "light",
        })

def login(request):
    logged_in_as = get_user(get_ip)
    username = ""
    password = ""
    try:
        username = request.POST["username"]
        password = request.POST["password"]
    except:
        if logged_in_as != "logged_out":
            return render(request, 'main/login.html', {
                "username": logged_in_as.username,
                "message": "Something went wrong!",
            })
        return render(request, 'main/login.html', {
            "message": "Something went wrong!",
        })
    else:
        if logged_in_as != "logged_out":
            logged_in_as.logged_in_as = "0"
            logged_in_as.save()
        if not username:
            if logged_in_as != "logged_out":
                return render(request, 'main/login.html', {
                    "username": logged_in_as.username,
                    "message": "Please enter a valid username!",
                })
            return render(request, 'main/login.html', {
                "message": "Please enter a valid username!",
            })
        if not password:
            if logged_in_as != "logged_out":
                return render(request, 'main/login.html', {
                    "username": logged_in_as.username,
                    "message": "Please enter a valid password!",
                })
            return render(request, 'main/login.html', {
                "message": "Please enter a valid password!",
            })
        for user in User.objects.all():
            if user.username == username:
                if user.password == password:
                    user.logged_in_as = get_ip(request)
                    user.save()
                    if logged_in_as != "logged_out":
                        logged_in_as.logged_in_as = "0"
                        logged_in_as.save()
                    return HttpResponseRedirect(reverse('index'))
            if user.email == username:
                if user.password == password:
                    user.logged_in_as = get_ip(request)
                    user.save()
                    if logged_in_as != "logged_out":
                        logged_in_as.logged_in_as = "0"
                        logged_in_as.save()
                    return HttpResponseRedirect(reverse('index'))
        if logged_in_as != "logged_out":
                return render(request, 'main/login.html', {
                    "username": logged_in_as.username,
                    "message": "The username or password is incorrect",
                })
        return render(request, 'main/login.html', {
            "message": "The username or password is incorrect",
        })
    
def sign_up(request):
    logged_in_as = get_user(get_ip)
    username = ""
    email = ""
    password = ""
    password2 = ""
    try:
        username = request.POST["username"]
        email = request.POST["email"]
        password = request.POST["password"]
        password2 = request.POST["password2"]
    except:
        if logged_in_as != "logged_out":
            return render(request, 'main/sign_up.html', {
                "username": logged_in_as.username,
                "message": "Something went wrong!",
            })
        return render(request, 'main/sign_up.html', {
            "message": "Something went wrong!",
        })
    else:
        if username == "":
            if logged_in_as != "logged_out":
                return render(request, 'main/login.html', {
                    "username": logged_in_as.username,
                    "message": "Please enter a valid username!",
                })
            return render(request, 'main/login.html', {
                "message": "Please enter a valid username!",
            })
        if email == "":
            if logged_in_as != "logged_out":
                return render(request, 'main/login.html', {
                    "username": logged_in_as.username,
                    "message": "Please enter a valid email!",
                })
            return render(request, 'main/login.html', {
                "message": "Please enter a valid email!",
            })
        if password == "":
            if logged_in_as != "logged_out":
                return render(request, 'main/login.html', {
                    "username": logged_in_as.username,
                    "message": "Please enter a valid password!",
                })
            return render(request, 'main/login.html', {
                "message": "Please enter a valid password!",
            })
        if password2 == "":
            if logged_in_as != "logged_out":
                return render(request, 'main/login.html', {
                    "username": logged_in_as.username,
                    "message": "Please fill in all the fields!",
                })
            return render(request, 'main/login.html', {
                "message": "Please fill in all the fields!",
            })
        for user in User.objects.all():
            if user.username == username:
                if logged_in_as != "logged_out":
                    return render(request, 'main/sign_up.html', {
                        "username": logged_in_as.username,
                        "message": "A user with that username already exists!",
                    })
                return render(request, 'main/sign_up.html', {
                    "message": "A user with that username already exists!",
                })
            if user.email == email:
                if logged_in_as != "logged_out":
                    return render(request, 'main/sign_up.html', {
                        "username": logged_in_as.username,
                        "message": "A user with that email already exists!",
                    })
                return render(request, 'main/sign_up.html', {
                    "message": "A user with that email already exists!",
                })
        if password != password2:
            if logged_in_as != "logged_out":
                return render(request, 'main/sign_up.html', {
                    "username": logged_in_as.username,
                    "message": "The passwords do not match!",
                })
            return render(request, 'main/sign_up.html', {
                "message": "The passwords do not match!",
            })
        if logged_in_as != "logged_out":
            logged_in_as.logged_in_as = "0"
            logged_in_as.save()
        user = User(username=username, email=email, password=password, logged_in_as=get_ip)
        user.save()
        return HttpResponseRedirect(reverse('index'))
    
def logout(request):
    user = get_user(get_ip(request))
    if user != "logged_out":
        user.logged_in_as = "0"
        user.save()
    try:
        path = request.POST["path"]
        return HttpResponseRedirect(path)
    except:
        return HttpResponseRedirect(reverse('index'))
        