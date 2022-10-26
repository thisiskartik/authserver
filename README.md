
# Auth Server
This is a template auth server to quickly start a Django App with Authentication built-in.

## Routes
- ```api/users/```:
  - ```GET```: Get details of Logged in user
  - ```PUT```: Update information of Logged in user
  - ```DELETE```: Delete the logged in user
- ```api/users/token```:
  - ```POST```: Get access and refresh token
    - ```email```: Email address of user
    - ```password```: Password of user
- ```api/users/token/refresh```:
  - ```POST```: Get new access token
    - ```refresh```: Pass the refresh token
- ```api/users/reigster```:
  - ```POST```: Register a new user
    - ```email```: Email of the new user
    - ```password```: Password of the new user
    - ```first_name```: User's first name
    - ```last_name```: User's last name
- ```api/users/verify```:
  - ```POST```: Verify new user
    - ```token```: Token got in mail when registered
    - ```id```: Token got in mail when registered
- ```api/users/reset-password```:
  - ```POST```: Request password reset
    - ```email```: Email address of the user
  - ```POST```: Reset user's password
    - ```token```: Token got in mail when reset requested
    - ```id```: ID got in mail when registered
    - ```password```: New password

## User Model
- ```first_name```
- ```last_name```
- ```email```
- ```is_staff```
- ```is_active```
- ```date_joined```