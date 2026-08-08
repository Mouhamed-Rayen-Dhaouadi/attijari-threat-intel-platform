from django import forms
from .models import ConfigurationAPI, ThreatIndicator, Investigation


class ConfigurationAPIForm(forms.ModelForm):
    class Meta:
        model = ConfigurationAPI
        # quota_consomme et date_derniere_utilisation restent en lecture
        # seule : ils sont gérés automatiquement par connecteurs.py, pas
        # par l'admin.
        fields = ['nom_fournisseur', 'cle_api', 'actif', 'quota_restant']
        widgets = {
            'cle_api': forms.PasswordInput(render_value=True),
        }


class AjoutManuelIOCForm(forms.Form):
    SEVERITES = [
        ('CRITIQUE', 'Critique'),
        ('ELEVE', 'Élevé'),
        ('MOYEN', 'Moyen'),
        ('FAIBLE', 'Faible / Sain'),
    ]

    champ_style = "w-full bg-attijari-void border border-slate-700 rounded-lg px-3 py-2.5 text-white text-sm outline-none focus:border-attijari-orange transition"

    indicator_value = forms.CharField(
        label="Valeur de l'indicateur", max_length=255,
        widget=forms.TextInput(attrs={'class': champ_style})
    )
    indicator_type = forms.ChoiceField(
        label="Type", choices=ThreatIndicator.INDICATOR_TYPES,
        widget=forms.Select(attrs={'class': champ_style})
    )
    severity = forms.ChoiceField(
        label="Sévérité", choices=SEVERITES,
        widget=forms.Select(attrs={'class': champ_style})
    )
    source = forms.ChoiceField(
        label="Source de la découverte",
        choices=[c for c in ThreatIndicator.SOURCES if c[0] != 'SCAN_AUTO'],
        widget=forms.Select(attrs={'class': champ_style})
    )
    description = forms.CharField(
        label="Description / justification",
        widget=forms.Textarea(attrs={'rows': 4, 'class': champ_style})
    )


class InvestigationForm(forms.ModelForm):
    champ_style = "w-full bg-attijari-void border border-slate-700 rounded-lg px-3 py-2.5 text-white text-sm outline-none focus:border-attijari-orange transition"

    class Meta:
        model = Investigation
        fields = ['titre', 'description', 'statut']
        widgets = {
            'titre': forms.TextInput(attrs={'class': "w-full bg-attijari-void border border-slate-700 rounded-lg px-3 py-2.5 text-white text-sm outline-none focus:border-attijari-orange transition"}),
            'description': forms.Textarea(attrs={'rows': 4, 'class': "w-full bg-attijari-void border border-slate-700 rounded-lg px-3 py-2.5 text-white text-sm outline-none focus:border-attijari-orange transition"}),
            'statut': forms.Select(attrs={'class': "w-full bg-attijari-void border border-slate-700 rounded-lg px-3 py-2.5 text-white text-sm outline-none focus:border-attijari-orange transition"}),
        }