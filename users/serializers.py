from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
User = get_user_model()

class MeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]

class EmailOrUsernameTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Login avec 'email' OU 'username' + 'password'.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields[self.username_field].required = False
        self.fields["email"] = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        data = self.initial_data or {}
        username_in = (data.get("username") or "").strip()
        email_in    = (data.get("email") or "").strip()
        password_in = (data.get("password") or "").strip()

        if not password_in or not (username_in or email_in):
            raise serializers.ValidationError({"detail": "Identifiants manquants."})

        login_value = username_in or email_in

        # chemin email
        if "@" in login_value:
            try:
                user = User.objects.get(email__iexact=login_value)
            except User.DoesNotExist:
                raise serializers.ValidationError({"detail": "Identifiants invalides."})
            attrs[self.username_field] = getattr(user, User.USERNAME_FIELD)
            attrs["password"] = password_in
            return super().validate(attrs)

        # chemin username
        if username_in and not attrs.get(self.username_field):
            attrs[self.username_field] = username_in
        if password_in and not attrs.get("password"):
            attrs["password"] = password_in
        return super().validate(attrs)