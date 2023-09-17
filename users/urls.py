'''
from django.contrib import admin
from django.urls import path, include
from users.views import api_signup

from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
#
from django.urls import path 
from .views import LoginView, RegisterView, user_login 
# from rest_framework_swagger.views import get_swagger_view

#schema_view = get_swagger_view(title='API Documentation')


schema_view = get_schema_view (
   openapi.Info(
      title="Snippets API",
      default_version='v1',
      description="Test visualAI",
      contact=openapi.Contact(email="nadabaabaa70@gmail.com"),
      license=openapi.License(name="BSD License"),
   ),
     public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [

    path('admin/', admin.site.urls),
     path('register/', RegisterView.as_view()),
         path('login/', user_login, name='login'),

   # path('login/', LoginView.as_view()),
    #path('user', UserView.as_view()),
    # path('logout', LogoutView.as_view()),
    # path('api/signup/', api_signup, name='api-signup'),
    # path('swagger/', schema_view),
    # path('api/signup/', api_signup, name='api-signup'),
    # path('swagger/', schema_view),
 
    #
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
  
    
]
'''
# accounts/urls.py

from django.urls import path ,include
from .views import register_user, user_login, user_logout
###
from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .views import change_password

##3
schema_view = get_schema_view(
   openapi.Info(
      title="Snippets API",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)
urlpatterns = [
    path('register/', register_user, name='register'),
    path('login/', user_login, name='login'),
    path('logout/', user_logout, name='logout'),
    path('api/password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),

    path('change_password/', change_password, name='change_password'),

    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
  
]
