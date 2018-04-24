#!/usr/bin/env python

import argparse
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import json
import os
import stat
import uuid

"""
================================================================================
Assignment: Simple storage server
Clone this wiki locally
	 Clone in Desktop
Description

This is an API specification for a simple HTTP-based multi-user file
storage server. Your assignment is to write a server that implements
this API using a language of your choice.

There are five API endpoints to implement:

POST /register

This endpoint is used to register as a new user. Usernames must be at
least 3 characters and no more than 20, and may only contain
alphanumeric characters. Passwords must be at least 8 characters.

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

This endpoint is used to log in as an existing user. On success, it
returns a session token. The session token should be included in
future requests to authenticate the sender.

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
GET /files/<filename>

This endpoint is used to get a file from the logged-in user's personal
storage.

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

To submit the assignment, put the code in a repository under your
GitHub account and send a link to the repository to your recruiter
contact at New Alchemy.

arifications;:

1. Scale - don't worry about scale at all for this exercise.  But very
interested on any thoughts written or in person on how you'd architect
this differently for service like:
  100k users 1m files 10 files upload concurrent peak   50 files download peak
  20m users  100m files 1k files upload concurrent peak   10k files download peak

2. security - don't work about wiring in HTTPS, though it's assumed
that's how we'd deploy it.  Do think about user A can't access user
B's file

3. file names - find some rational limitations.  uploading the same
file should not collide with the previous.  How would that work given
the GET file API?

4. logout - don't implement logout or session expiration.  you can
talk to it if you'd like.  All good.

~Ken

Responses to clarifications:
1. Scale--implemented as toy scale, using python objects instead of a
   DB. This also means the file server has no Durability, and the
   Atomicity, Consistency and Isolation are due in part to the Global Interpreter
   Lock (this is written for Python 2.7.10).

      The first scaling goal (  100k users 1m files 10 files upload
      concurrent peak   50 files download peak) could be done with a single
      server with a capable back end DB. The routines to get and set data
      would be reimplemented with an ORM like Peewee, backed by MySQL, for
      example. If performance goals are not reached by Python, I would
      either use the methods below in the second scaling goals or
      reimplement in Java or C++. The structure would otherwise be very
      similar, optimizations applied where measurements indicate they would
      be fruitful.

      The second scaling goal (  20m users  100m files 1k files upload
      concurrent peak   10k files download peak) would require scaling
      the API servers horizontally, and may require partitioning both
      the actual file store as well as the database. Depending of the
      rates of registration and login requests, the partitioning could
      be dynamic, with the API layer broadcasting a request to be
      answered by the DB server that has the answer, or, if the
      network traffic is too heavy, statically partitioned with each
      API server knowing which DB server has the user info. The API
      server fleet would be fronted by a load balancer with the
      ability to bind sessions to API servers, so an API server could
      cache all the file data for a logged in user session. If
      multiple concurrent logins of the same user is allowed, either
      all active used sessions would need to be handled by the same
      API server, or the file servers would have to be aware of which
      API servers a given user had sessions on so cache updates could
      be pushed.

      The translation of service file name to file system file name
      would be handled by a DB as well, with an autogenerated
      field. THat way, the user dat is interpreted only as a string
      and cannot be gamed to gain access to other files. This
      translation could happen on the ffile servers, if they are
      partitioned by users, but likely we could get better utilization
      by load balancing file servers by fullness (on file PUTs) and
      recording the location in the DB that is partitioned by user
      name.

      In any case, I would implement, measure and tune.

2. Security. I can add SSL/TLS and the necessary infrastructure to
   this Python version, but it would take time away from design and
   development to show what I can do operationally. Regarding keeping
   files private to their owners, the design that maps each user to
   their own storage "bucket" (directory, perhaps, on a POSIX system)
   and then keeps them separate by disassociating the users' names for
   files and how they are stored. In order to impement multiple files
   with the same name for a given user, we have to do some sore of
   mapping, and using, for example,. an autoincrement field big
   integer as part of the filename (after converting it to a numeric
   string) avoids all the issues with the user injecting specific
   characters into the file name for effect (such as ..), therby
   keeping each user confined to their bucker.

3. This suggests to me a versioning filesystem. So, to stay within the
   given API, I will implement a stack. So, if you upload two files of
   the same name, the GET will return the last one. If you DELETE it, you
   can GET the previous version if any. This necessitates divorcing the
   file service file name from the real file name if the filesystem is
   used as the file store.

4. With neither session expiration or explicit logout, the security
   attack serface is increased. If the session key is ever leaked
   anywhere, the seriousness is proportional to its durability. We
   could force as session inactivity timeout and a periodic session
   rekey. Anything that limits how long a session key, if stolen,
   would be good for helps unless it promotes less secure behavior on
   the part of the end users. Forced rotation of passwords in the
   current environment is an example of this.

"""

# These would be in a DB in scaled code
users = {}                      # dict of registered usernames and passwords
sessions = {}                   # dict of current user sessions, by sessionid

class user:
    """
    Holds user name, password, and a dictionary of file names as known to the
    user and a list of files known to the file server. Mailtains a stack of
    files with the same user facing name. FIles are names for the user with a
    monotonically increasing filenumber. May need to reinvestigate if our user
    creat and delete tons of files...
    """
    def __init__(self, name, password):
        self.name = name
        self.password = password
        self.files = dict()
        self.fileNumber = 0

    def put_file(self, fn):
        """
        Returns the name of the file to write in the underlying file system
        """
        filelst = self.files.get(fn, [])
        filenm = self.name + "." + str(self.fileNumber)
        self.fileNumber += 1
        filelst.append(filenm)
        self.files[fn] = filelst
        return filenm

    def get_file(self, fn):
        """
        Returns the file to read in the underlying file systerm or None
        """
        filelst = self.files.get(fn, None)
        # Returns the name of the file in the filesystem if it exists, or None.
        return filelst[-1] if filelst else None

    def delete_file(self, fn):
        """
        Returns the file in the underlying file system to delete, if any, or None.
        """
        filelst = self.files.get(fn, None)
        if filelst:
            filenm = filelst.pop()
            if filelst:
                self.files[fn] = filelst
            else:
                self.files.pop(fn)
            return filenm
        return None


class RequestHandler(BaseHTTPRequestHandler):

    def safe_print(self, data):
        """
        For safe logging to the terminal. The only control characters that are
        passed are \\r and \\n, all others are ^ escaped. Bytes with the MSB set
        are printed in hex with the \\xhh escape sequence. Notice that this means
        you cannot tell carat followed by a capital letter from a control character.
        """
        bai = bytearray(data)
        bao = bytearray(0)      # zero length to start
        for x in bai:
            if x in (10, 13):
                bao.append(x)
            elif x < 32:
                bao.append(94)  # ^
                bao.append(x + 64)
            elif x < 127:
                bao.append(x)
            elif x == 127:
                bao.append(94)  # ^
                bao.append(63)  # ?
            else:
                bao.append(92)    # backslash
                bao.append(120)    #  x
                hexy = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100,
                        101, 102]
                bao.append(hexy[(x>>4) & 0xf])
                bao.append(hexy[x&0xf])
        print str(bao)

    def print_request_start(self, command):
        print "\n----- Request %s %s ----->\n" % (command, self.path)
        print self.headers

    def print_request_end(self, command, status, data=None, response=None):
        """
        data is data that is sent to the client, response is part of the status
        response.
        """
        if data:
            self.safe_print(data)
        trailer = command, self.path, status, response
        print "<----- Request %s  %s %s %s -----\n" % trailer

    def do_register(self, data):
        errmsg = []
        jsonData = {}
        try:
            jsonData = json.loads(data)
        except Exception as e:
            errmsg.append("Bad JSON: %s" % e.message)
        username = jsonData.get(u"username", None) if data else None
        password = jsonData.get(u"password", None) if data else None

        # validate username at least 3 and no more than 20 alphanumeric characters
        if username is None:
            errmsg.append("Must supply a username between 3 and 20 characters.")
        elif len(username) < 3:
            errmsg.append("username must be at least 3 characters.")
        elif len(username) > 20:
            errmsg.append("Username must be at most 20 characters.")
        elif not username.isalnum():
            errmsg.append("Username can only contain alphanumeric characters.")
        elif users.get(username, None) is not None:
            errmsg.append("Username %s already in use!" % username)

        # validate password is at least 8 characters
        if password is None:
            errmsg.append("You must supply a password of at least 8 characters.")
        elif len(password) < 8:
            errmsg.append("Password must be at least 8 characters.")
        if len(errmsg) > 0:
            self.error_content_type = "application/json"
            errorJson = '{ "error": "%s" }' % errmsg
            self.print_request_end("POST", 400, data=data, response=errorJson)
            self.send_error(400, errorJson)
        else:
            users[username] = user(username, password)
            self.print_request_end("POST", 200, data=data)
            self.send_response(204)

    def do_login(self, data):
        errmsg = []
        jsonData = {}
        try:
            jsonData = json.loads(data)
        except Exception as e:
            errmsg.append("Bad JSON: %s" % e.message)

        username = jsonData.get(u"username", None) if data else None
        password = jsonData.get(u"password", None) if data else None
        user = users.get(username, None)
        # IRl would hash the password
        realPassword = user.password if user else None
        if realPassword is None or realPassword != password:
            # Must be vague to foil attacks
            # IRL would also sleep for a few seconds.
            errmsg.append("Wrong username or password.")
        if len(errmsg) > 0:
            self.error_content_type = "application/json"
            errorJson = '{ "error": "%s" }' % errmsg
            self.print_request_end("POST", 403, data=data, response=errorJson)
            self.send_error(403, errorJson)
        else:
            sessionId = uuid.uuid4().hex
            self.print_request_end("POST", 200, data=data, response=jsonData)
            sessions[sessionId] = user

            # bug data sent back to the client must start with a newline.
            jsonData = u'\n{ "token": "%s" }\n' % sessionId
            self.send_response(200, jsonData)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(jsonData))
            self.wfile.write(jsonData)

    def do_POST(self):
        self.print_request_start("POST")

        lengths = self.headers.getheaders('content-length')
        length = int(lengths[0]) if lengths else 0
        data = self.rfile.read(length)

        if self.path == "/register":
            self.do_register(data)
        elif self.path == "/login":
            self.do_login(data)
        else:
            self.print_request_end("POST", 404, data=data)
            self.send_error(404)

    def do_GET(self):
        self.print_request_start("GET")
        session = self.headers.getheaders("X-Session")
        session = session[0] if session else None
        if session is None:
            self.send_error(403, "Forbidden")
            return
        thisUser = sessions.get(session, None)
        if thisUser is None:
            self.send_error(403, "Forbidden")
            return

        if not self.path.startswith("/files"):
            self.print_request_end("PUT", 404, data=data)
            self.send_error(404, "No such endpoint")
            return
        if not self.path.startswith("/files/"):
            # Is list command. Nore that the server won't send data to the
            # client unless it stars with a newline. Feature or bug,,,
            jsonData = "\n" + json.dumps(thisUser.files.keys())
            self.print_request_end("GET", 200, data=jsonData[:80], response="OK")
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(jsonData))
            self.wfile.write(jsonData)
            return

        filenm = self.path[len("/files/"):]
        filenm = thisUser.get_file(filenm)
        if filenm is None:
            self.print_request_end("GET", 404, response="Not found")
            self.send_error(404, "Not found")
            return

        stbuf = os.stat(filenm)
        length = stbuf[stat.ST_SIZE]
        self.print_request_end("GET", 200, data="<%s bytes>"%length)
        self.send_response(200, "OK")
        self.send_header("Content-Length", length)
        # TODO mick -- This loop will run us out of memory on large file
        # transfers, fix
        with open(filenm, "r") as f:
            data = f.read(length)
            self.wfile.write(data)

    def do_PUT(self):
        self.print_request_start("PUT")
        # TODO mick--extract common subexpressions with do_GET, particularly the
        # logged in check.
        session = self.headers.getheaders("X-Session")
        session = session[0] if session else None
        if session is None:
            self.send_error(403, "Forbidden")
            return
        thisUser = sessions.get(session, None)
        if thisUser is None:
            self.send_error(403, "Forbidden")
            return

        if not self.path.startswith("/files/"):
            self.print_request_end("PUT", 404, response="No such endpoint")
            self.send_error(404, "No such endpoint")
            return
        filenm = self.path[len("/files/"):]
        filenm = thisUser.put_file(filenm)
        lengths = self.headers.getheaders('content-length')
        length = int(lengths[0]) if lengths else 0
        # TODO mick - this loop won't handle large files, will run out of
        # memory, fix.
        with open(filenm, "w") as f:
            data = self.rfile.read(length)
            f.write(data)
        data = "<%s bytes>" % length
        self.print_request_end("PUT", 201, data=data[:80], response="Created")
        self.send_response(201, "Created")
        self.send_header("Location", self.path)

    def do_DELETE(self):
        self.print_request_start("DE:ETE")
        # TODO mick -- pull out common logged in code
        session = self.headers.getheaders("X-Session")
        session = session[0] if session else None
        if session is None:
            self.send_error(403, "Forbidden")
            return
        thisUser = sessions.get(session, None)
        if thisUser is None:
            self.send_error(403, "Forbidden")
            return

        if not self.path.startswith("/files/"):
            self.print_request_end("DELETE", 404, response="No such endpoint")
            self.send_error(404, "No such endpoint")
            return

        filenm = self.path[len("/files/"):]
        filenm = thisUser.delete_file(filenm)
        if filenm is None:
            self.print_request_end("DELETE", 404, response="Not found")
            self.send_error(404, "Not found")
            return
        os.unlink(filenm)
        self.print_request_end("DELETE", 204, data=self.path)
        self.send_response(204)

def main():
    parser = argparse.ArgumentParser(description="Simple storage server")
    parser.add_argument("serverPort", type=int, nargs='?', default=8080)
    args = parser.parse_args()
    port = args.serverPort
    print('Listening on localhost:%s' % port)
    server = HTTPServer(('', port), RequestHandler)
    server.serve_forever()


if __name__ == '__main__':
    main()

