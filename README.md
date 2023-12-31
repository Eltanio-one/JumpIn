# JumpIn
A web app designed to minimise time spent waiting for machines in the gym, allowing gymgoers who plan to use the same machines for their routines to "Jump In" together and maximise their time.
Please note that although this app is full-stack, front-end was not prioritised during development.

Any gym can create an account, and then list their available machines that users can plan to use in a session. If any machines are under repair, the gym can list this and it will update the available machines that are shown to the users.
When users create an account, they can register to their gym to enable session planning. Planning a session is the crux of JumpIn, where a user lists 5 machines in order they wish to use, and the JumpIn algorithm will search through a lobby of other users sessions and return a list of optimal JumpIn partners to each user based on how similarly matched the sessions are.
Users can then send a session request to the user they want to JumpIn with, and this user can accept or decline the request and start a chat with the requester to organise when to meet and JumpIn.

JumpIn v1 was created by Dan Haver, who can be contacted via [email](mailto:haverd08@gmail.com).

## Technologies
Front-End: HTML5, CSS, Bootstrap, JavaScript.

Back-end: Python, Flask, Jinja2, Postgresql, Psycopg2.

## Features

## Communal

### Login, Register and Logout
- The login page contains all paths for registering and logging in to the JumpIn app. When registering, users provide their personal details, before their password is hashed for security and their created account is stored in the postgresql database.
- When logging in, recaptcha-v3 is used to protect against potential abusive traffic. The same goes for when gym accounts register and log in. All acounts follow the same route when logging out, and will be redirected to the login page.

## User-Specific

### User Profile
- Displays user details, including account information, top 5 used machines and their registered gyms available machines.
- Functionality for changing the user password, deleting the account, and adding their registered gym are also available on the user profile.

### Plan a Session
- Users can plan their session to submit to the JumpIn lobby here. Only machines that are available at their current gym will be shown in the form, and once submitted, the user must wait for the lobby to have at least two people before the algorithm will be executed.
- Two algorithms are executed, one to generate an output for each member of the lobby with their closest matching lobby members, and another to generate an output for each lobby member with which machines and in what order they are matching with other lobby members.
- Based on the outputs of the two algorithms, users can choose a user to JumpIn with and submit a session request.

### Session Requests
- The session requests page is the hub for all results of planned sessions. Requests the user has sent to others requesting a JumpIn session can be seen here and cancelled if needed.
- Requests that have been sent by other users can be accepted or declined, and if accepted the user can start a private chat with the user, whom must accept the chat request, to organise their JumpIn meet up.
- Chat requests that other users have sent to the current user are shown here too for them to accept or decline.

### Chatting
- Once a requestee has accepted the session request of a requester, the option to chat using a chatroom created using socketio is available. A unique chatroom is generated only accessible by the two users, and messages are dynamically presented to each user to enable them to organise when to meet and/or exchange details etc. Once the chat is complete, the room is deleted and messages removed.

## Gym-Specific

### Gym Profile
- Differs from the user profile in that information is not shown, but links to add opening times which will be shown to users (implementation in v2), add machines the gym owns, note machines which are under repair which will be reflected in the choices members of that gym have during session plans, and changing password/deleting the account are stored here.

# Version 2 Plans
I plan to add functionality to contact me via SMTP, and improve the front-end of the app.
