from django import forms
from django.contrib.auth.models import User
from .models import UserProfile


class UtilisateurCreationForm(forms.ModelForm):
    """
    Formulaire de création d'un utilisateur complet : les champs du
    User natif de Django + le rôle (stocké dans UserProfile).
    """
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput,
        min_length=8,
    )
    role = forms.ChoiceField(
        label="Rôle",
        choices=UserProfile.ROLES,
    )

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()
            # Le signal a déjà créé un UserProfile par défaut (ANALYST) ;
            # on le met à jour avec le rôle réellement choisi dans le formulaire.
            user.profile.role = self.cleaned_data['role']
            user.profile.save()
        return user


class UtilisateurEditForm(forms.ModelForm):
    """
    Formulaire de modification : mêmes champs, mais sans mot de passe
    obligatoire (on ne force pas à le changer à chaque édition).
    """
    role = forms.ChoiceField(
        label="Rôle",
        choices=UserProfile.ROLES,
    )

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email']

    def save(self, commit=True):
        user = super().save(commit=commit)
        if commit:
            user.profile.role = self.cleaned_data['role']
            user.profile.save()
        return user