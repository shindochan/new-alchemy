"""
Assignment: Simple storage server
Clone this wiki locally
	 Clone in Desktop
Description

This is an API specification for a simple HTTP-based multi-user file storage server. Your assignment is to write a server that implements this API using a language of your choice.

There are five API endpoints to implement:

POST /register

This endpoint is used to register as a new user. Usernames must be at least 3 characters and no more than 20, and may only contain alphanumeric characters. Passwords must be at least 8 characters.

Request

Content-Type: application/json

{
  "username": "the username of the user to create",
  "password": "the password of the user to create"
}
Response (success)

Status: 204 No Content
Response (failure)

Status: 400 Bad Request
Content-Type: application/json

{
  "error": "explanation of failure"
}
POST /login

This endpoint is used to log in as an existing user. On success, it returns a session token. The session token should be included in future requests to authenticate the sender.

Request

Content-Type: application/json

{
  "username": "the username of the user to log in as",
  "password": "the password of the user to log in as"
}
Response (success)

Status: 200 OK
Content-Type: application/json

{
  "token": "an opaque session token"
}
Response (failure)

Status: 403 Forbidden
Content-Type: application/json

{
  "error": "explanation of failure"
}
PUT /files/<filename>

This endpoint is used to upload a file to the logged-in user's personal storage.

Request

Content-Length: <file size>
Content-Type: <content type>
X-Session: <session token>

<file bytes>
Response (success)

Status: 201 Created
Location: /files/<filename>
GET /files/<filename>

This endpoint is used to get a file from the logged-in user's personal storage.

Request

X-Session: <session token>
Response (success)

Status: 200 OK
Content-Length: <file size>
Content-Type: <content type>

<file bytes>
Response (not logged in)

Status: 403 Forbidden
Response (not found)

Status: 404 Not Found
DELETE /files/<filename>

This endpoint is used to delete a file from the user's personal storage.

Request

X-Session: <session token>
Response (success)

Status: 204 No Content
Response (not logged in)

Status: 403 Forbidden
Response (not found)

Status: 404 Not Found
GET /files

This endpoint is used to list files in this user's personal storage.

Request

X-Session: <session token>
Response (success)

Content-Type: application/json

[
  <filenames...>
]
Response (not logged in)

Status: 403 Forbidden
Submission

To submit the assignment, put the code in a repository under your GitHub account and send a link to the repository to your recruiter contact at New Alchemy.

1. Scale - don't worry about scale at all for this exercise.  But very interested on any thoughts written or in person on how you'd architect this differently for service like:
100k users 1m files 10 files upload concurrent peak   50 files download peak
20m users  100m files 1k files upload concurrent peak   10k files download peak
2. security - don't work about wiring in HTTPS, though it's assumed that's how we'd deploy it.  Do think about user A can't access user B's file
3. file names - find some rational limitations.  uploading the same file should not collide with the previous.  How would that work given the GET file API?
4. logout - don't implement logout or session expiration.  you can talk to it if you'd like.  All good.

~Ken

This suggests to me a versioning filesystem. So, to stay within the
given API, I will implement a stack. So, if you upload two files of
the same name, the GET will return the last one. If you DELETE it, you
can GET the previous version if any. This necessitates divorcing the
file service file name from the real file name if the filesystem is
used as the file store.


"""
import json
import requests

host = "localhost"
port = "8080"
url = "http://" + host + ":" + port + "/"

"""
POST /register

This endpoint is used to register as a new user. Usernames must be at least 3 characters and no more than 20, and may only contain alphanumeric characters. Passwords must be at least 8 characters.

Request

Content-Type: application/json

{
  "username": "the username of the user to create",
  "password": "the password of the user to create"
}
Response (success)

Status: 204 No Content
Response (failure)

Status: 400 Bad Request
Content-Type: application/json

{
  "error": "explanation of failure"
}

"""
def get_token(r):
    """
    Work around for a bug in requests module that misses json in POST
    replies.
"""
    return json.loads(r.text.splitlines()[-1]).get("token", None)

def do_post(endpoint, expected_status, payload=None, *args):
    requestURL = url + endpoint
    r = requests.post(requestURL, data=(payload % args if payload else None))
    assert r.status_code == expected_status
    return r

def do_register(username, password, status):
    payload = '{ "username": "%s", "password": "%s" }'
    do_post("register", status, payload, username, password)

def testregister():
    """
    POST /register
    Registers a username/password pair. This test should be run on a
    newly created 'database' as it expects to be able to create the
    test user the first time and not the second. Because of this, all
    tests for this end point are asserts for this single test. Tests the
    follo0wing cases:
    1> User name correct length (3-20 characters)
    2> User name valid character set (alphanumerics)
    3> Password at least 8 characters
    4> duplicate user
    5> success (returns 204, no content)
    All failure return status code 400 and a JSON object with the
    field "error" set to ta string error message.
    """
    do_post("register", 400)      # No post data, fails

    # Check for legal username length
    username = ''
    password = "legalButBad"
    for i in range(22):
        usernameLen = len(username)
        if usernameLen < 3 or usernameLen > 20:
            do_register(username, password, 400)
        else:
            do_register(username, password, 204)
        username = username + "a"

    # Check character set. Note, can't start with 'aa', already used above
    ba = bytearray("abc")
    for i in range(256):
        ba[2] = i
        username = str(ba)
        if username.isalnum():
            do_register(username, password, 204)
        else:
            do_register(username, password, 400)

    # Check for legal password length
    username = "user3"
    password = ""
    for i in range(9):
        if len(password) < 8:
            do_register(username, password, 400)
        else:
            do_register(username, password, 204)
        password = password + "a"

    # Check for success, followed by duplicate entry
    username = "user4"
    password = "12345678"
    do_register(username, password, 204)

    password = "87654321"       # same user, different password, fail
    do_register(username, password, 400)

def do_login(username, password, expected_status):
    requestURL = url + "login"
    payload = '{ "username": "%s", "password": "%s" }' % (username, password)
    r = requests.post(requestURL, data=payload)
    assert r.status_code == expected_status
    return r


def test_login():
    """
    POST /login

    This endpoint is used to log in as an existing user. On success,
    it returns a session token. The session token should be included
    in future requests to authenticate the sender.

    Request

    Content-Type: application/json

    {
    "username": "the username of the user to log in as",
    "password": "the password of the user to log in as"
    }
    Response (success)

    Status: 200 OK
    Content-Type: application/json

    {
        "token": "an opaque session token"
    }
    Response (failure)

    Status: 403 Forbidden
    Content-Type: application/json

    {
        "error": "explanation of failure"
    }
    """
    username = "noneexistant"
    password = "testpassword"
    do_login(username, password, 403)
    username = "logintest"
    do_register(username, password, 204)
    do_login(username, "badpasword", 403)
    r = do_login(username, password, 200)
    assert(get_token(r) is not None)

def do_put_file(filename, status, data, token=None):
    urlTail = "files/" + filename
    requestURL = url + urlTail
    headers = dict()
    if token is not None:
        headers["X-Session"] = token
    r = requests.put(requestURL, data=data, headers=headers)
    assert(r.status_code == status)
    if status == 201:
        assert(r.headers.get("Location", None) == "/" + urlTail)
    return r

def test_put_file():
    """
    PUT /files/<filename>

    This endpoint is used to upload a file to the logged-in user's
    personal storage.

    Request

    Content-Length: <file size>
    Content-Type: <content type>
    X-Session: <session token>

    <file bytes>
    Response (success)

    Status: 201 Created
    Location: /files/<filename>

    file names - find some rational limitations.  uploading the same file
    should not collide with the previous.  How would that work given the
    GET file API?

    """
    username = "testput"
    password = "testpassword"
    data1 = "test data v1"
    data2 = "test data v2"
    do_register(username, password, 204)
    do_put_file("test1", 403, data1)   # Not logged In
    r = do_login(username, password, 200)
    token = get_token(r)
    do_put_file("test1", 201, data1, token)
    do_put_file("test1", 201, data2, token) # duplicate names work.
    do_put_file("test2", 201, None, token)

def do_get_file(filename, expected_status, token=None):
    """
    Note: returns a Reponse object which has an open connection! If
    the returned object is r, you must either call r.close() or use r
    as a context manager as in 'with do_get_file(...) as r:'
    """

    requestURL = url + "files/" + filename
    headers = dict()
    if token is not None:
        headers["X-Session"] = token
    r = requests.get(requestURL, headers=headers, stream=True)
    assert(r.status_code == expected_status)
    return r

def test_get_file():
    """
    GET /files/<filename>

    This endpoint is used to get a file from the logged-in user's
    personal storage.

    Request

        X-Session: <session token>
    Response (success)

      Status: 200 OK
      Content-Length: <file size>
      Content-Type: <content type>

      <file bytes>
    Response (not logged in)

      Status: 403 Forbidden
      Response (not found)

      Status: 404 Not Found
    """
    username = "testget"
    password = "testpassword"
    data1 = "test data v1"
    data2 = "longer test data v2"
    do_register(username, password, 204)
    r = do_login(username, password, 200)
    token = get_token(r)
    do_put_file("test1", 201, data1, token)
    username="testget2"
    do_register(username, password, 204)
    r = do_login(username, password, 200)
    token = get_token(r)
    with do_get_file("test1", 403):   # no token, so not logged in
        pass
    with do_get_file("tes1", 404, token): # This user hasn't written yet
        pass
    do_put_file("test1", 201, data1, token)
    with do_get_file("test1", 200, token) as r:
        assert(r.headers["Content-Length"] == str(len(data1)))
        for line in r.iter_lines():
            assert(line == data1)
    do_put_file("test1", 201, data2, token) # duplicate names work.
    with do_get_file("test1", 200, token) as r:
        assert(r.headers["Content-Length"] == str(len(data2)))
        for line in r.iter_lines():
            assert(line == data2)
    do_put_file("test2", 201, None, token)
    with do_get_file("test2", 200, token) as r:
        assert(r.headers["Content-Length"] == "0")
        for line in r.iter_lines():
            assert(False)           # empty file, should not be reached

def do_delete(filename, expected_status, token=None):
    requestURL = url + "files/" + filename
    headers = dict()
    if token is not None:
        headers["X-Session"] = token
    r = requests.delete(requestURL, headers=headers)
    assert(r.status_code == expected_status)

def test_delete():
    """DELETE /files/<filename>

    This endpoint is used to delete a file from the user's personal
    storage.

    Request

      X-Session: <session token>
    Response (success)

      Status: 204 No Content
    Response (not logged in)

      Status: 403 Forbidden
    Response (not found)

      Status: 404 Not Found

    3. file names - find some rational limitations.  uploading the
    same file should not collide with the previous.  How would that
    work given the GET file API?

    This suggests to me a versioning filesystem. So, to stay within
    the given API, I will implement a stack. So, if you upload two
    files of the same name, the GET will return the last one. If you
    DELETE it, you can GET the previous version if any. This
    necessitates divorcing the file service file name from the real
    file name if the filesystem is used as the file store.
    """
    username = "testdelete"
    password = "testpassword"
    data1 = "test data v1"
    data2 = "longer test data v2"
    filename="test1"
    do_register(username, password, 204)
    r = do_login(username, password, 200)
    token = get_token(r)
    do_put_file(filename, 201, data1, token)
    do_put_file(filename, 201, data2, token) # duplicate names work.

    do_delete(filename, 403)     # no token, not logged in
    with do_get_file(filename, 200, token) as r:
        assert(r.headers["Content-Length"] == str(len(data2)))
        for line in r.iter_lines():
            assert(line == data2)

    # data2 version of file1 was most recent. If we delete it, we
    # should wee the previous version
    do_delete(filename, 204, token)
    with do_get_file(filename, 200, token) as r:
        assert(r.headers["Content-Length"] == str(len(data1)))
        for line in r.iter_lines():
            assert(line == data1)

    do_delete(filename, 204, token)
    # just deleted last copy, get file should fail
    with do_get_file(filename, 404, token):
        pass

    # now, delete should fail
    do_delete(filename, 404, token)

def do_list(expected_status, count, token=None):
    requestURL = url + "files"
    headers = dict()
    if token is not None:
        headers["X-Session"] = token
    r = requests.get(requestURL, headers=headers, stream=True)
    if r.status_code != 200:
        return r
    with r:
        assert(r.status_code == expected_status)
        content = []
        for line in r.iter_lines():
            if content:
                content.append(line)
            elif line.startswith("["):
                content.append(line)
        jsonData = json.loads(" ".join(content)) if content else []
        assert(len(jsonData) == count)
    return r


def test_get_file_list():
    """
    GET /files

    This endpoint is used to list files in this user's personal
    storage.

    Request

      X-Session: <session token>
    Response (success)

      Content-Type: application/json

      [
        <filenames...>
      ]
    Response (not logged in)

      Status: 403 Forbidden
    """
    username = "testlist"
    password = "testpassword"
    data1 = "test data v1"
    data2 = "longer test data v2"
    filename1="test1"
    filename2="test2"
    do_register(username, password, 204)
    r = do_login(username, password, 200)
    token = get_token(r)
    do_put_file(filename1, 201, data1, token)
    do_put_file(filename1, 201, data2, token) # duplicate names work.
    do_put_file(filename2, 201, None, token)

    do_list(403, 0)     # no token, not logged inswd
    do_list(200, 2, token)

    do_delete(filename1, 204, token)
    do_list(200, 2, token)      # file had previous version, count unchanged

    do_delete(filename1, 204, token)
    do_list(200, 1, token)

    do_delete(filename2, 204, token)
    do_list(200, 0, token)
