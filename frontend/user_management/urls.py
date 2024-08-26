from django.urls import path, include

urlpatterns = [
    path('', include('user.urls')),
    path('admin/', include('admin_account.urls'))
]
