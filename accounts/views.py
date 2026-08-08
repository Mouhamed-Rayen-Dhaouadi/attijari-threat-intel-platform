from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.urls import reverse_lazy

from accounts.decorators import role_required
from .forms import UtilisateurCreationForm, UtilisateurEditForm


class RoleBasedLoginView(LoginView):
    template_name = 'accounts/login.html'

    def get_success_url(self):
        role = self.request.user.profile.role
        if role == 'VIEWER':
            return reverse_lazy('dashboard')
        return reverse_lazy('ioc_scanner')


@role_required('ADMIN')
def liste_utilisateurs_view(request):
    utilisateurs = User.objects.all().select_related('profile').order_by('username')
    return render(request, 'accounts/liste_utilisateurs.html', {'utilisateurs': utilisateurs})


@role_required('ADMIN')
def creer_utilisateur_view(request):
    if request.method == "POST":
        form = UtilisateurCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Utilisateur créé avec succès.")
            return redirect('liste_utilisateurs')
    else:
        form = UtilisateurCreationForm()

    return render(request, 'accounts/form_utilisateur.html', {'form': form, 'mode': 'creation'})


@role_required('ADMIN')
def modifier_utilisateur_view(request, user_id):
    utilisateur = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        form = UtilisateurEditForm(request.POST, instance=utilisateur)
        if form.is_valid():
            form.save()
            messages.success(request, "Utilisateur modifié avec succès.")
            return redirect('liste_utilisateurs')
    else:
        form = UtilisateurEditForm(instance=utilisateur, initial={'role': utilisateur.profile.role})

    return render(request, 'accounts/form_utilisateur.html', {'form': form, 'mode': 'edition', 'utilisateur': utilisateur})


@role_required('ADMIN')
def supprimer_utilisateur_view(request, user_id):
    utilisateur = get_object_or_404(User, id=user_id)

    # 🔒 Un admin ne peut pas se supprimer lui-même.
    if utilisateur == request.user:
        messages.error(request, "Vous ne pouvez pas supprimer votre propre compte.")
        return redirect('liste_utilisateurs')

    if request.method == "POST":
        utilisateur.delete()
        messages.success(request, "Utilisateur supprimé.")
        return redirect('liste_utilisateurs')

    return render(request, 'accounts/confirmer_suppression.html', {'utilisateur': utilisateur})