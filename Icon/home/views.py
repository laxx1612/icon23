from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics, permissions, viewsets
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.settings import api_settings
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.models import Token
from django.core.files.storage import default_storage
from django.conf import settings
from django.http import JsonResponse
from .models import Events
from django.views.decorators.csrf import csrf_exempt

from .models import *
from .serializers import *
# Create your views here.

@csrf_exempt
@api_view(['GET'])
@permission_classes([permissions.DjangoModelPermissionsOrAnonReadOnly])
def student_list(request):
    students = Students.objects.all()
    serializer = StudentsSerializer(students, many=True)
    return Response(serializer.data)

def event_names(request):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    events = Events.objects.all()
    event_names = [event.title for event in events]
    return JsonResponse(event_names, safe=False)    


class CustomUserCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.AllowAny]



class CustomAuthTokenView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        response = super(CustomAuthTokenView, self).post(request, *args, **kwargs)
        token = response.data['token']
        user = CustomUser.objects.get(auth_token=token)
        return Response({'token': token, 'email': user.email})


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request, format=None):
        email = request.data.get('email')
        password = request.data.get('password')
        print(email, password)
        user = authenticate(request, username=email, password=password)
        print(user)
        if user is not None:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            user_obj=CustomUser.objects.get(email=email)
            # student=Students.objects.get(email=user_obj)
            student=user_obj.students_set.first()
            print(student)
            return Response({'token': token.key, 'user_id':user.id,'user_name':student.name,'success':True}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    


class LogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Get the user's token
        token = request.auth
        # Delete the token
        token.delete()
        return Response({'message': 'Logged out successfully.'})
    


class StudentListCreateView(generics.ListCreateAPIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = Students.objects.all()
    serializer_class = StudentsSerializer

    def post(self, request, *args, **kwargs):
        # Print the received authentication token from frontend
        auth_token = request.auth
        print("Received authentication token:",auth_token)
        print(request.data)
        email=request.user
        user=CustomUser.objects.get(email=email)
        print(user)
        print(request.user)
        data = {
            'name': request.data.get('name'),
            'college': request.data.get('college'),
            'dept': request.data.get('dept'),
            'year': request.data.get('year'),
            'email': user, 
            'ph_no': request.data.get('ph_no'),
            'id_card': request.data.get('id_card'),
        }

        # Create a Student object
        student = Students(**data)
        # student.save()
        id_card_image = request.FILES.get('id_card')
        if id_card_image:
            student.id_card.save(id_card_image.name, id_card_image, save=True)
        student.save()    
        # response = super().post(request, *args, **kwargs)
        print("response")
        return Response({"message": "Student object created successfully."})

# class StudentListCreateView(generics.ListCreateAPIView):
#     queryset = Students.objects.all()
#     serializer_class = StudentsSerializer

#     def perform_create(self, serializer):
#         serializer.save()  # This saves the validated data

#     def post(self, request, *args, **kwargs):
#         # Deserialize the incoming data
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         print(serializer.data)
#         return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)



class StudentDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Students.objects.all()
    serializer_class = StudentsSerializer
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        print(instance.get_id_card_url())
        serializer = self.get_serializer(instance)
        print("Student Detail Response:", serializer.data)  # Print the response data
        image_path = 'ID_Cards/giri.png'
        image_url = default_storage.url(image_path)
        print("Generated Image URL:", settings.MEDIA_URL + image_url)
        return Response(serializer.data)



class RegistrationCreateView(generics.CreateAPIView):
    queryset = Registration.objects.all()
    serializer_class = RegistrationSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        # Access the data from the request here
        event_id = self.request.data.get('event')
        student_id = self.request.data.get('student')
        is_paid = self.request.data.get('is_paid')
        
        print("Received data from frontend:")
        print("Event ID:", event_id)
        print("Student ID:", student_id)
        print("Is Paid:", is_paid)
        
        # Continue with creating the instance using the serializer
        serializer.save()

    def post(self, request, *args, **kwargs):
        # Print the data received from the frontend
        print("Received data from frontend:")
        print("Request data:", request.data)
        event = self.request.data.get('event')
        student_id = self.request.data.get('student')
        student_name=self.request.data.get('name')
        is_paid = self.request.data.get('is_paid')
        event_instance=Events.objects.get(title=event)
        student_instance = Students.objects.get(pk=student_id)
        # print(student_instance,type(student_instance),type(event_instance))
        try:
            registration=Registration(event=event_instance,student=student_instance)
            registration.save()
            serializer=RegistrationSerializer(registration)
            
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)   
           


class RegisteredEventsView(generics.ListAPIView):
    serializer_class = RegistrationSerializer

    def get_queryset(self):
        # Get the student_id from the URL parameters
        student_id = self.kwargs['student_id']
        # Filter registrations by the student_id
        queryset = Registration.objects.filter(student__id=student_id)
        return queryset
    


class EventsByCategoryView(generics.ListAPIView):
    serializer_class = EventsSerializer

    def get_queryset(self):
        # Get the category from the URL parameters
        category = self.kwargs['category']
        # Filter events by the category
        queryset = Events.objects.filter(category=category)
        return queryset
    


class TeamsListCreateView(generics.ListCreateAPIView):
    queryset = Teams.objects.all()
    serializer_class = TeamsSerializer



class TeamsDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Teams.objects.all()
    serializer_class = TeamsSerializer