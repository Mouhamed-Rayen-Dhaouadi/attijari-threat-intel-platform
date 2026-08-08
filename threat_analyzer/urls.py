from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('', views.ioc_scanner_view, name='ioc_scanner'),
    path('database/', views.database_view, name='database'),
    path('exporter-pdf/<str:ioc_value>/', views.exporter_pdf_view, name='exporter_pdf'),

    path('api-config/', views.liste_api_view, name='liste_api'),
    path('api-config/creer/', views.creer_api_view, name='creer_api'),
    path('api-config/<int:config_id>/modifier/', views.modifier_api_view, name='modifier_api'),
    path('api-config/<int:config_id>/supprimer/', views.supprimer_api_view, name='supprimer_api'),
    path('ajouter-ioc/', views.ajouter_ioc_manuel_view, name='ajouter_ioc_manuel'),
    path('menace/confirmer/<str:ioc_value>/', views.confirmer_menace_view, name='confirmer_menace'),
path('menaces/', views.liste_menaces_view, name='liste_menaces'),
path('deploiement/ajouter/<int:menace_id>/', views.ajouter_file_deploiement_view, name='ajouter_file_deploiement'),
path('deploiement/', views.liste_deploiement_view, name='liste_deploiement'),
path('deploiement/<int:deploiement_id>/retirer/', views.retirer_file_deploiement_view, name='retirer_file_deploiement'),
path('decouverte-ioc/', views.decouverte_ioc_view, name='decouverte_ioc'),
path('decouverte-ioc/ajouter/', views.ajouter_ioc_decouvert_view, name='ajouter_ioc_decouvert'),
path('investigations/', views.liste_investigations_view, name='liste_investigations'),
path('investigations/creer/', views.creer_investigation_view, name='creer_investigation'),
path('investigations/<int:investigation_id>/', views.detail_investigation_view, name='detail_investigation'),
path('investigations/<int:investigation_id>/retirer/<int:ioc_id>/', views.retirer_ioc_investigation_view, name='retirer_ioc_investigation'),

]