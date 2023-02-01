import jwt
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, exceptions
from django.http import HttpResponse
from django.contrib.auth.models import User
from .models import RegisteredUser, UserContacts, UserContactMapping
from .serializers import RegisteredUserSerializer, UserContactsSerializer
from django.contrib.auth import authenticate
from rest_framework.authentication import get_authorization_header, BaseAuthentication

# Create your views here.
def home(request):
    return HttpResponse('Home Page')


"""RegisterUser registers the users,
Takes username, password, phone_number, email(optional)
"""
class RegisterUser(APIView):
    def post(self, request, format=None):
        username = request.data.get('username')
        phone_no = request.data.get('phone_no', None)
        email = request.data.get('email', None)
        password = request.data.get('password')
        
        user = User(
            username=username,
            password=password,
            email=email,
        )


        if user:
            user.set_password(password)
            user.save()

            registerUser = RegisteredUser.objects.create(
                registeredUser=user,
                phone_number=phone_no,
                email=email,
            )
            body = {
                'id' : user.id,
                'username' : user.username
            }
        
            jwtToken = {'Success': RegisteredUserSerializer(registerUser).data,

            'Bearer': jwt.encode(body, "SECRET_KEY")}

            return Response(data=jwtToken, status = status.HTTP_201_CREATED)
        else:
            return Response(data={'Error': "Error Registering User"}, status = status.HTTP_400_BAD_REQUEST)


"""SignIn logs in the users,
Takes username and password
"""
class SignIn(APIView):
    def post(self, request):
        if not request.data.get('username') or not request.data.get('password'):
            return Response(data={'Error': "username/password not found"})
        username = request.data.get('username')
        password = request.data.get('password')

        if username and password:
            if (authenticate(username=username, password=password)):
                user = User.objects.get(username=username)
            else:
                return Response({'Error': "Invalid username/password"}, status = status.HTTP_400_BAD_REQUEST)

            if user:
                body = {
                    'id': user.id,
                    'username': user.username,
                }

                jwtToken = {'Success' : "Sign in Successful!",
                    'Username' : user.username,
                    'Bearer': jwt.encode(body, "SECRET_KEY")}

                return Response(data=jwtToken, status = status.HTTP_201_CREATED)
            else:
                return Response(data={'Error': "Invalid Credentials"}, status = status.HTTP_401_UNAUTHORIZED)
                


"""CreateContact create and saves the currently logged in user's contact,
Takes name, phone_number, email(optional)
"""
class CreateContact(APIView):
    def get(self, request):
        userContacts = UserContacts.objects.all()
        serialized = UserContactsSerializer(userContacts, many=True)
        return Response(data=serialized.data)
    
    def post(self, request):
        obj = AuthenticateToken()
        user, error = obj.authenticateToken(request)
        if error:
            return Response(data=error, status=status.HTTP_401_UNAUTHORIZED)
        else:
            name = request.data.get("name")
            phone = request.data.get("phone_no")
            email = request.data.get("email")
            userContact = UserContacts(name=name, phone_number=phone, email=email)
            userContact.save()

            userContactMapped = UserContactMapping(user=user, userContact=userContact)              #Mapping with the currently logged in User.
            userContactMapped.save()

            body = {
                'msg': "User Contact Saved",
                'data': request.data
            }
            return Response(data=body, status=status.HTTP_201_CREATED)


"""AuthenticateToken authenticates the users for making API calls,
Takes Token
"""
class AuthenticateToken(BaseAuthentication):
    def authenticateToken(self, request):
        authToken = get_authorization_header(request).split()
        if not authToken or authToken[0].lower() != b'bearer': 
            return ('', {'Error':"Unauthorized Access !!! Invalid Token"})
        if len(authToken)==1 or len(authToken)>2:
            msg= 'Invalid token header/No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        
        try:
            token = authToken[1]
            if token == 'null':
                msg = 'No Token Found'
                raise exceptions.AuthenticationFailed(msg)
        except UnicodeError:
            msg = 'Invalid token header.'
            raise exceptions.AuthenticationFailed(msg)

        return self.verifyCredentials(token)

    def verifyCredentials(self, token):
        try:
            body = jwt.decode(token, "SECRET_KEY")
            username = body['username']
            id = body['id']
            user = User.objects.get(
                username=username,
                id=id,
                is_active=True
            )
        except:
            return ('', {'Error': "Invalid Token"})
        return (user, '')


"""SearchByPhoneNo Searched for the users with the phone number,
Takes phone number
"""
class SearchByPhoneNo(APIView):
    def get(self, request):
        phone = request.data.get('phone_no')

        try:
            obj = AuthenticateToken()
            user, error = obj.authenticateToken(request)
            if error:
                return Response(data=error, status=status.HTTP_401_UNAUTHORIZED)
            else:
                numberOwner = RegisteredUser.objects.get(phone_number=phone)
                
                if numberOwner:
                    user = User.objects.get(id=numberOwner.id, is_active=True)
                response = {
                    'name':user.username,
                    'phone no':numberOwner.phone_number,
                    'spam':numberOwner.spam,
                    'email':numberOwner.email
                }
                return Response(data=response, status=status.HTTP_302_FOUND)
        except RegisteredUser.DoesNotExist:
            userContacts = UserContacts.objects.all().filter(phone_number=phone)
            response=[]
            for userContact in userContacts:
                response.append({
                    'name': userContact.name,
                    'phone': userContact.phone_number,
                    'spam': userContact.spam,
                    'email': userContact.email
                })
            
            if len(response)<1:
                return Response(data={'Error': "Contact Not Found"}, status=status.HTTP_404_NOT_FOUND)
            return Response(data=response, status=status.HTTP_302_FOUND)

        except:
            return Response(data={'Error':"Internal Server Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



"""MarkSpam marks the users as spam,
Takes phone number
"""
class MarkSpam(APIView):
    def post(self, request):
        try:
            obj = AuthenticateToken()
            user, error = obj.authenticateToken(request)
            if error:
                return Response(data=error, status=status.HTTP_401_UNAUTHORIZED)
            else:
                phone = request.data.get('phone_no')
                contactUpdate = UserContacts.objects.filter(phone_number=phone).update(spam=True)
                userUpdate = RegisteredUser.objects.filter(phone_number=phone).update(spam=True)

                if (contactUpdate + userUpdate):
                    return Response(data={'message': "Contact marked as spam"},status=status.HTTP_200_OK)
                else:
                    return Response(data={'message': "Contact Not Found"},status=status.HTTP_404_NOT_FOUND)

        except:
            return Response(data={'Error': "Internal server error"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SearchByName(APIView):
    def get(self, request):
        try:
            obj = AuthenticateToken()
            user, error = obj.authenticateToken(request)
            if error:
                return Response(data=error, status=status.HTTP_401_UNAUTHORIZED)
            else:
                name = request.data.get('name')
                userStartBy = RegisteredUser.objects.all().filter(registeredUser__username__startswith=name)
                userContains = RegisteredUser.objects.all().filter(registeredUser__username__contains=name).exclude(registeredUser__username__startswith=name)
                contactStartBy = UserContacts.objects.all().filter(name__startswith=name)
                contactContains = UserContacts.objects.all().filter(name__contains=name).exclude(name__startswith=name)

                response=[]
                for contact in userStartBy:
                    response.append({
                        'name': contact.registeredUser.username,
                        'phone': contact.phone_number,
                        'spam': contact.spam
                    })
                for contact in contactStartBy:
                    response.append({
                        'name': contact.name,
                        'phone': contact.phone_number,
                        'spam': contact.spam
                    })
                for contact in userContains:
                    response.append({
                        'name': contact.registeredUser.username,
                        'phone': contact.phone_number,
                        'spam': contact.spam
                    })
                for contact in contactContains:
                    response.append({
                        'name': contact.name,
                        'phone': contact.phone_number,
                        'spam': contact.spam
                    })
                return Response(data=response, status=status.HTTP_200_OK)
        
        except:
            return Response(data={'Error': "Internal Server Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)