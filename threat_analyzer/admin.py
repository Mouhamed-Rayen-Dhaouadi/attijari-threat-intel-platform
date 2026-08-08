from django.contrib import admin
from .models import ThreatIndicator, ConfigurationAPI # Assure-toi d'importer ConfigurationAPI

admin.site.register(ThreatIndicator)
admin.site.register(ConfigurationAPI) # On enregistre le modèle de configuration