from django.urls import path
from django.contrib.auth import views as auth_views
from .views import (
    RoleBasedLoginView,
    liste_utilisateurs_view,
    creer_utilisateur_view,
    modifier_utilisateur_view,
    supprimer_utilisateur_view,
)

urlpatterns = [
    path('login/', RoleBasedLoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),

    path('utilisateurs/', liste_utilisateurs_view, name='liste_utilisateurs'),
    path('utilisateurs/creer/', creer_utilisateur_view, name='creer_utilisateur'),
    path('utilisateurs/<int:user_id>/modifier/', modifier_utilisateur_view, name='modifier_utilisateur'),
    path('utilisateurs/<int:user_id>/supprimer/', supprimer_utilisateur_view, name='supprimer_utilisateur'),
]