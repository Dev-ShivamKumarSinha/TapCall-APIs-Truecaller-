from django.urls import path
from . import views

urlpatterns = [
    path('',views.home),
    path('register/',views.RegisterUser.as_view()),
    path('signin/', views.SignIn.as_view()),
    path('contacts/', views.CreateContact.as_view()),
    path('find_contact_by_number/', views.SearchByPhoneNo.as_view()),
    path('spam/', views.MarkSpam.as_view()),
    path('find_contact_by_name/', views.SearchByName.as_view()),
]
