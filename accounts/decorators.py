from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from functools import wraps


def role_required(*roles_autorises):
    """
    Décorateur qui vérifie que l'utilisateur connecté a l'un des rôles
    autorisés. Vérifie aussi qu'il est connecté (login_required inclus).

    Exemple d'utilisation :
        @role_required('ADMIN')
        def ma_vue(request): ...

        @role_required('ANALYST', 'ADMIN')
        def autre_vue(request): ...
    """
    def decorateur(vue):
        @login_required
        @wraps(vue)
        def wrapper(request, *args, **kwargs):
            if request.user.profile.role not in roles_autorises:
                raise PermissionDenied
            return vue(request, *args, **kwargs)
        return wrapper
    return decorateur