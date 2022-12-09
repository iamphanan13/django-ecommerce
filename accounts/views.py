from django.shortcuts import render, redirect
from .forms import RegistratonForm
from .models import Account
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
# Create your views here.

# import verification mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage



# function đăng ký
def register(request):
    if request.method == 'POST':
        form = RegistratonForm(request.POST) #Lấy dữ liệu từ form
        if form.is_valid(): #Kiểm tra dữ liệu hợp lệ
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split('@')[0]

            user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()

            # Kích hoạt tài khoản
            current_site = get_current_site(request)
            mail_subject = 'Please activate your account'
            message = render_to_string('accounts/account_verification_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })

            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            # messages.success(request, 'Vui lòng kiểm tra email để kích hoạt tài khoản')
            return redirect('/accounts/login/?command=verification&email='+email)


    else:
        form = RegistratonForm()
    context = {
        'form': form
    }
    return render(request, 'accounts/register.html', context )

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            auth.login(request, user)
            messages.success(request, 'Đăng nhập thành công')
            return redirect('dashboard')
        else:
            messages.error(request, 'Sai email hoặc mật khẩu')
            return redirect('login')
    return render(request, 'accounts/login.html' )


@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'Đăng xuất thành công')
    return redirect('login')

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Kích hoạt tài khoản thành công')
        return redirect('login')
    else:
        messages.error(request, 'Đường link kích hoạt không hợp lệ')
        return redirect('register')

# dashboard
@login_required(login_url='login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')


def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)

            # Reset lại password
            current_site = get_current_site(request)
            mail_subject = 'Yêu cầu reset lại mật khẩu'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })

            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            messages.success(request, 'Vui lòng kiểm tra email để reset lại mật khẩu')
            return redirect('login')
        else:
            messages.error(request, 'Email không tồn tại')
            return redirect('forgotPassword')

    return render(request, 'accounts/forgotPassword.html')

def resetpassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Vui lòng nhập mật khẩu mới')
        return redirect('resetPassword')
    else:
        messages.error(request, 'Đường link reset mật khẩu không hợp lệ')
        return redirect('login')

def resetPassword(request):
    return render(request, 'accounts/resetPassword.html')