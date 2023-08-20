from django.contrib import admin
from .models import *

# Register your models here.

class CustomUserAdmin(admin.ModelAdmin):
    list_filter = ['email']
    list_display = ['email']
    search_fields = ['email']

    class Meta:
        model = CustomUser

admin.site.register(CustomUser, CustomUserAdmin)



class StudentsAdmin(admin.ModelAdmin):
    list_filter = ['name', 'college']
    list_display = ['name', 'college', 'dept', 'ph_no']
    search_fields = ['name', 'college', 'dept', 'ph_no']

    class Meta:
        model = Students

admin.site.register(Students, StudentsAdmin)



class EventsAdmin(admin.ModelAdmin):
    list_filter = ['title', 'category']
    list_display = ['title', 'category', 'date', 'event_time', 'cordinator']
    search_fields = ['title', 'category', 'date', 'event_time', 'cordinator']

    class Meta:
        model = Events

admin.site.register(Events, EventsAdmin)



class FacultyInchargeAdmin(admin.ModelAdmin):
    list_filter = ['fac_name']
    list_display = ['fac_name', 'event_incharge']
    search_fields = ['fac_name', 'event_incharge']

    class Meta:
        model = FacultyIncharge

admin.site.register(FacultyIncharge, FacultyInchargeAdmin)



class RegistrationAdmin(admin.ModelAdmin):
    list_filter = ['event', 'student', 'is_paid']
    list_display = ['event', 'student', 'registered_at']
    search_fields = ['event', 'student']

    class Meta:
        model = Registration

admin.site.register(Registration, RegistrationAdmin)



class TeamsAdmin(admin.ModelAdmin):
    list_filter = ['team_lead', 'team_member', 'event']
    list_display = ['team_lead', 'event']
    search_fields = ['team_lead', 'team_member', 'event']

    class Meta:
        model = Teams

admin.site.register(Teams, TeamsAdmin)