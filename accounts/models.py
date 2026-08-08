from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    ROLES = [
        ('ANALYST', 'Analyste SOC'),
        ('ADMIN', 'Administrateur'),
        ('VIEWER', 'Consultation / Statistiques'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=10, choices=ROLES, default='ANALYST')

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"