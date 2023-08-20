from rest_framework import serializers
from .models import Students, Events, Registration, FacultyIncharge, Teams, CustomUser


class StudentsSerializer(serializers.ModelSerializer):
    #  id_card = serializers.ImageField(source='id_card.url', read_only=True)
     class Meta:
        model = Students
        fields = '__all__'
        



class EventsSerializer(serializers.ModelSerializer):
     class Meta:
        model = Events
        fields = '__all__'



class RegistrationSerializer(serializers.ModelSerializer):
     class Meta:
        model = Registration
        fields = '__all__'



class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user



class FacultyInchargeSerializer(serializers.ModelSerializer):
     class Meta:
        model = FacultyIncharge
        fields = '__all__'



class TeamsSerializer(serializers.ModelSerializer):
     class Meta:
        model = Teams
        fields = '__all__'