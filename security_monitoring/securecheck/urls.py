from django.urls import path
from . import views
from .views import Pdf

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.registerPage, name='register'),
    path('login/', views.loginPage, name='login'),
    path('logout/', views.logoutUser, name='logout'),
    path('newanalytics/', views.newanalytics, name='newanalytics'),
    #path('email/', views.email, name='email'),
    path('certificates_pdf/', views.new, name='newpdf'),
    path('badenc_pdf/', views.keys, name='newkeyspdf'),
    path('revoked_pdf', views.revoked, name='revokedpdf'),
    path('total_certs', views.tcerts, name='tcerts'),
    path('total_keys', views.tkeys, name='tkeys'),
    path('exp_certs', views.ecerts, name='ecerts'),
    path('expcerts', views.expcertss, name='expcerts'),
    path('testing', views.testing, name='testing'),
    path('badkeys', views.bkeys, name='bkeys'),
    #path('delrec/', views.deleterec, name='delrec'),
    path('rev_certs', views.rcerts, name='rcerts'),
    path('Delete/<int:id>', views.anothertest, name='another_test'),
    path('Delete_certs/<int:id>', views.total_certs_page, name='total_certs_page'),
    path('update/<int:id>', views.onemoretest, name='onemoretest'),
    path('info/<int:id>', views.newinfo, name='new_info'),
    path('notify/', views.notify, name='notify'),
    path('location/<int:id>', views.location, name='location'),
    path('pass/', views.givepass, name='pass'),
    path('pass_word/', views.passdata, name='pass_user'),
    path('Delete_keys/<int:key_id>', views.keystest, name='keystest'),
    path('update_keys/<int:key_id>', views.keys_update, name='updatekeys'),
    path('onlyenc', views.not_enc, name='notenc'),
    path('onlylen/', views.not_len, name='notlen'),
    #path('update_keys/<int:id>', views.updatekeys, name='updatekeys'),
]