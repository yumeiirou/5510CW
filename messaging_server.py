"""
messaging_server.py - SKELETON

The server has three jobs:
  1. Register users and publish the public information others need to
     communicate with them (a directory).
  2. Work out which user is making each request.
  3. Relay envelopes between users. Envelopes wait in the recipient's mailbox
     until the recipient's client collects them.

HOW THIS SKELETON WORKS
-----------------------
The HTTP handling, routing, the user directory and mailboxes are
provided and work. The security-critical functions are not: each one raises
NotImplementedError, so the server will not run until you have written them.
Each function's docstring says what it must achieve. It is up to you how to
achieve each goal.

Sections are marked as follows:

  PROVIDED - DO NOT MODIFY   Needed by the functionality test script. Changing
                             these may cause the test to fail.
  PROVIDED - MAY MODIFY      Working plumbing. Change it if your design needs to.
  TODO                       Not written yet. Raises NotImplementedError.


PROTOCOL FLOW
-------------
The skeleton supports secure messaging protocols of the following general
shape. The exact design is yours; this shows how the pieces fit together and
which function you write for each step. Alice is sending a message to Bob.

  1. Client identity. The client generates its long-term keys and obtains a
     client ID. Clients exchange IDs out of band.
       -> Complete create_identity (client); load_keys (client)

  2. Secure channel to the server. The client establishes a secure channel
     and checks it is talking to the genuine server. Once a secure channel is established,
     the server authenticates EVERY request a client makes, including lookups and sending. (SR1, SR2)
       -> Complete setup_server_security (server); URL_SCHEME (client); server_options (client); auth_headers (client); get_caller (server)

  3. Register. The client registers its ID and public information.
       -> Complete check_registration (server); registration on the client-side happends in create_identity and the provided register function

  4. Look up a peer. The client asks the server for Bob's public information
     and verifies it really belongs to the ID it was given out of band.
       -> Complete verify_contact_keys (client)

  5. Agree a key. The client agrees a shared secret key with Bob, relayed
     through the server but not learnable by it. The exchange is
     authenticated, so each side knows who it is talking to. (SR3, SR4)
       -> Complete agree_key (client), and any helpers you add

  6. Exchange messages. The two clients exchange messages through the server,
     encrypted and authenticated under the shared key, so the server sees
     only ciphertext. (SR5)
       -> Complete send_message (client); handle_envelope (client); unprotect_message (client)

In this script, you must modify the following sections of code (described in the protocol flow above):
    - Add imports
    - setup_server_security function
    - get_caller function
    - check_registration function
    - check_envelope function

You may also add new functions, endpoints (see ROUTES), and global state if you wish.

Command-line arguments (DO NOT rename or remove; you may add new ones):
  --host      hostname to listen on (default: localhost)
  --port      port to listen on (default: 8443)
  --insecure  run with security measures weakened, for Part 2
Any files your server creates must be written to the current working directory.

INSECURE MODE (Part 2)
----------------------
When the server is started with --insecure, the global INSECURE is True.
It is set before setup_server_security is called, so any function can check
it. Use it to disable or weaken the specific defences your Part 2 attacks
target, for example:

    if not INSECURE:
        ...check that the envelope's "from" matches the caller...

Everything else must keep working in insecure mode. Document exactly what
INSECURE changes in your README.
"""

import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ===========================================================================
# TODO: Add any imports you need here.
# You may use any standard Python libraries.
# You must use cryptography.io for all cryptographic functions.
# Your implementation must work on SCC machines.
# ===========================================================================


INSECURE = False      # True when started with --insecure (Part 2)
MAX_BODY_BYTES = 64 * 1024


# ===========================================================================
# PROVIDED - MAY MODIFY: helpers
# ===========================================================================


def b64e(data: bytes) -> str:
    """Bytes -> base64 text, for putting keys, signatures etc. into JSON."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Base64 text -> bytes. Raises ValueError on invalid input."""
    return base64.b64decode(text.encode("ascii"), validate=True)


def encode_fields(label: str, *fields) -> bytes:
    """Encode several values into one unambiguous byte string.

    Useful whenever you sign, hash or authenticate more than one value at
    once. Each field is length-prefixed, so ("ab", "c") and ("a", "bc")
    encode differently. The label lets you keep different uses apart.
    Fields may be str or bytes.
    """
    out = bytearray()
    for item in (label, *fields):
        if isinstance(item, str):
            item = item.encode("utf-8")
        out += len(item).to_bytes(4, "big") + item
    return bytes(out)


class APIError(Exception):
    """Raise inside a handler to send an error response, e.g. APIError(401, "bad auth")."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Request:
    """What a handler receives.

    req.method   "GET" or "POST"
    req.path     the request path, e.g. "/lookup/alice"
    req.arg      for prefix routes, the part of the path after the prefix ("alice")
    req.headers  the HTTP headers (dict-like)
    req.body     the JSON body as a dict ({} if there is no body)
    req.raw_body the body exactly as received, as bytes (b"" if there is no body).
                 Use this if you need to check a signature or MAC over the body.
    """

    def __init__(self, method, path, arg, headers, body, raw_body=b""):
        self.method, self.path, self.arg, self.headers = method, path, arg, headers
        self.body, self.raw_body = body, raw_body


# ===========================================================================
# Server state (in memory). PROVIDED - MAY MODIFY: add whatever you need.
# ===========================================================================

LOCK = threading.Lock()  # hold this whenever you read or change shared state
USERS = {}               # client ID -> {"name": ..., "public_info": {...}}
NAMES = {}               # username -> client ID (usernames must be unique)
MAILBOXES = {}           # client ID -> list of envelopes waiting for collection


# ----------------------------------------------------------------------
# TODO: Protect the channel to clients in function setup_server_security.
# This is the server's side of protocol flow step 2.
# It secures the connection and lets clients check they are talking
# to the genuine server, not an impostor (SR1). The client side is in
# URL_SCHEME and server_options; the two must match.
# ----------------------------------------------------------------------

def setup_server_security(httpd: ThreadingHTTPServer, host: str) -> ThreadingHTTPServer:
    """
    Protect the channel between the server and its clients, and return the
    (modified) server. Called once by main, before the server starts accepting
    connections. 

    host is the hostname clients will use to reach the server.
    """
    # 1. Set up whatever your chosen secure protocol needs. If the server
    #    proves its identity with external data, create the data and any 
    #    cryptographic keys here. 

    # 2. Create any files in the current working directory, only if they are
    #    missing, and reuse them if they already exist (so the identity does
    #    not change each start). Keep private files private; clients will need
    #    the public part (see the client's server_options).

    # 3. Wrap httpd so the connection is protected, and return it.
    raise NotImplementedError("TODO: setup_server_security")


# ===========================================================================
# TODO: Identify the user making a request in function get_caller.
# This is the server's side of SR2, and runs on EVERY request except
# registration. It checks the proof added by the client's auth_headers; the
# two functions must match.
# ===========================================================================


def get_caller(req: Request) -> str:
    """
    Return the client ID of the user making this request, or raise
    APIError(401) if the request does not prove who sent it. 

    Called for every request except registration. It must work with the
    client's auth_headers: whatever that returns arrives here in req.headers.
    A claimed client ID on its own proves nothing; anyone can send one.

    Why this matters: mailboxes are not encrypted. If the server cannot tell
    who is asking, anyone could read or empty another user's mailbox.

    Useful information:
      req.headers                     the headers the client sent
      req.method, req.path, req.raw_body   the details of this request
      USERS                           each user's registered public information
    """
    # 1. Read the proof the client put in req.headers (see auth_headers), and
    #    the client ID it claims to be.

    # 2. Look up that user's registered public information in USERS, and check
    #    the proof against it. Think about what stops someone replaying a copy
    #    of an earlier request. Hold LOCK while reading shared state.

    # 3. If the proof is valid, return the client ID. If anything is missing or
    #    fails, raise APIError(401). You may add endpoints to ROUTES if your
    #    design needs them.

    raise NotImplementedError("TODO: get_caller")


# ===========================================================================
# Endpoints. PROVIDED - MAY MODIFY,
# ===========================================================================

def handle_register(req: Request) -> dict:
    """POST /register - store a new user in the directory. Provided.

    Called when a client starts. Pulls client_id, name and public_info from
    the request, runs your check_registration function on them, and stores the user so
    others can look them up. Restarting a client with identical details succeeds.
    Sent without authentication, because the user does not exist yet."""
    
    try:
        client_id = str(req.body["client_id"])
        name = str(req.body["name"])
        public_info = req.body["public_info"]
    except (KeyError, TypeError):
        raise APIError(400, "malformed registration")
    if not client_id or any(c.isspace() for c in client_id):
        raise APIError(400, "client IDs must be non-empty and contain no whitespace")
    if not (1 <= len(name) <= 32) or not name.isprintable():
        raise APIError(400, "invalid username")
    if not isinstance(public_info, dict):
        raise APIError(400, "public_info must be a JSON object")

    record = {"name": name, "public_info": public_info}
    with LOCK:
        if USERS.get(client_id) == record:
            return {"client_id": client_id}   # same details: already registered
    check_registration(client_id, name, public_info)
    with LOCK:
        if client_id in USERS:
            raise APIError(409, "client ID already registered")
        if name in NAMES:
            raise APIError(409, "username already taken")
        USERS[client_id] = record
        NAMES[name] = client_id
        MAILBOXES[client_id] = []
    return {"client_id": client_id}


def handle_lookup(req: Request) -> dict:
    """GET /lookup/<client ID> - return a user's stored record. Provided.

    Lets one client fetch another's public information so it can message them.
    Authenticates the caller with your get_caller first. The client receiving
    this record must still verify it (see the client's verify_contact_keys)."""

    get_caller(req)
    with LOCK:
        record = USERS.get(req.arg)
    if record is None:
        raise APIError(404, "unknown client")
    return {"client_id": req.arg, **record}


def handle_send(req: Request) -> dict:
    """POST /send - put a message in the recipient's mailbox. Provided.

    Authenticates the caller (get_caller), checks the envelope is allowed
    (check_envelope), then queues it for the recipient to collect later. The
    server only relays the envelope; it cannot read an encrypted message."""

    caller = get_caller(req)
    envelope = req.body
    check_envelope(caller, envelope)
    recipient = envelope.get("to")
    with LOCK:
        if recipient not in MAILBOXES:
            raise APIError(404, "unknown recipient")
        MAILBOXES[recipient].append(envelope)
    return {"status": "queued"}


def handle_receive(req: Request) -> dict:
    """GET /receive - hand over and clear the caller's mailbox. Provided.

    Authenticates the caller (get_caller) and returns the envelopes waiting for
    them, emptying the mailbox. The client's background poller calls this about
    once a second, which is how messages arrive without user action."""

    caller = get_caller(req)
    with LOCK:
        envelopes = MAILBOXES.get(caller, [])
        MAILBOXES[caller] = []
    return {"envelopes": envelopes}


# Map (method, path) to handler. A path ending in "/" is a prefix route: it
# matches any path that starts with it, and the remainder becomes req.arg.
# You may add your own endpoints here if your design needs them.
ROUTES = {
    ("POST", "/register"): handle_register,
    ("GET", "/lookup/"): handle_lookup,
    ("POST", "/send"): handle_send,
    ("GET", "/receive"): handle_receive,
}


# ===========================================================================
# TODO: Endpoint checks, in functions check_registration and check_envelope.
# The endpoints themselves (register, lookup, send, receive) are provided and
# call into these two functions, which you write. Both are access control at
# the SERVER: check_registration guards what goes into the directory
# (supporting clients' key checks, SR4), and check_envelope stops a user
# sending messages in someone else's name (SR2).
# ===========================================================================


def check_registration(client_id: str, name: str, public_info: dict) -> None:
    """
    Check a new user's registration before it is stored. Raise APIError(400,
    ...) if it should be refused. 

    public_info is the public information the client sent (see the client's
    create_identity). Not called when a user restarts a client with identical
    details.

    Why this matters: without this check, anyone who learns Bob's client ID
    could register it first with their own public information, locking Bob out.
    (This does not replace the clients' own checks: clients still verify keys in verify_contact_keys.)
    """
    # 1. Check public_info is well formed (the fields your clients expect are
    #    present and the right type).

    # 2. Check it really belongs to client_id: the same relationship between
    #    the ID and the keys that a client checks in verify_contact_keys.

    # 3. If anything is wrong, raise APIError(400, ...). Otherwise return
    #    (handle_register will store the user).
    raise NotImplementedError("TODO: check_registration")



def check_envelope(caller: str, envelope: dict) -> None:
    """
    Check an envelope before handle_send queues it. Raise APIError(403, ...)
    if it should be refused. 

    caller is the client ID returned by get_caller: the user who proved they
    sent this request. The envelope's "from" field is written by the client.

    This is access control at the server. Recipients must still check for
    themselves who a message came from (see the client's unprotect_message).
    """
    # 1. Compare the envelope's "from" field with caller.

    # 2. If they do not match, raise APIError(403, ...) so a user cannot send
    #    messages in another user's name. Add any other checks your design
    #    needs. Otherwise return (handle_send will queue the message).
    raise NotImplementedError("TODO: check_envelope")







# ===========================================================================
# PROVIDED - MAY MODIFY: HTTP 
# ===========================================================================


class Handler(BaseHTTPRequestHandler):
    """Handles one incoming HTTP request. Provided; you should not need to
    change this. For each request it finds the matching endpoint (see ROUTES),
    reads the body, calls the endpoint, and sends back the JSON reply. The
    server runs these on several threads at once, which is why your server code
    must hold LOCK when touching shared state."""

    protocol_version = "HTTP/1.1"

    def _find_route(self, method, path):
        """Find the endpoint function for this method and path (see ROUTES).
        A path ending in "/" matches any path starting with it, and the rest
        becomes req.arg (e.g. /lookup/<id>). Raises 404 if nothing matches."""
        if (method, path) in ROUTES:
            return ROUTES[(method, path)], ""
        for (m, prefix), handler in ROUTES.items():
            if m == method and prefix.endswith("/") and path.startswith(prefix) and len(path) > len(prefix):
                return handler, path[len(prefix):]
        raise APIError(404, "not found")

    def _read_body(self):
        """Read the request body and return it both as raw bytes and as a
        parsed JSON dict. The raw bytes are kept so your get_caller can check a
        signature over exactly what was sent. Rejects oversized or invalid
        bodies."""
        """Return (raw bytes, parsed JSON dict) for the request body."""
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY_BYTES:
            raise APIError(413, "request too large")
        if length == 0:
            return b"", {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise APIError(400, "invalid JSON")
        if not isinstance(data, dict):
            raise APIError(400, "expected a JSON object")
        return raw, data

    def _send_json(self, status: int, payload: dict) -> None:
        """Send a JSON reply with the given status code."""
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self, method: str) -> None:
        """Run one request end to end: find the endpoint, read the body, call
        it, and send the result. If an endpoint raises APIError, its status and
        message are returned; any other error becomes a generic 500 (so a bug
        never leaks a stack trace to the client)."""
        try:
            path = self.path.split("?")[0]
            handler, arg = self._find_route(method, path)
            raw, body = self._read_body()
            self._send_json(200, handler(Request(method, path, arg, self.headers, body, raw)))
        except APIError as e:
            self._send_json(e.status, {"error": e.message})
        except Exception as e:  # never send a stack trace to the client
            print(f"[server] internal error: {e!r}")
            self._send_json(500, {"error": "internal error"})

    def do_GET(self):
        """Called by Python for each GET request."""
        self._dispatch("GET")

    def do_POST(self):
        """Called by Python for each POST request."""
        self._dispatch("POST")

    def log_message(self, fmt, *args):
        """Print a short log line for each request."""
        print(f"[server] {self.address_string()} {fmt % args}")


# ===========================================================================
# PROVIDED - DO NOT MODIFY (you may add arguments)
# ===========================================================================


def main():
    """Start the server and run it until interrupted. Provided; you should not
    need to change this (though you may add command-line arguments).

    It reads the command-line arguments, builds the HTTP server, hands it to
    your setup_server_security to protect the channel, and then serves requests
    until you stop it with Ctrl-C."""
    global INSECURE
    parser = argparse.ArgumentParser(description="Messaging server")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--insecure", action="store_true", help="weaken security (Part 2)")
    args = parser.parse_args()
    INSECURE = args.insecure # read by your code to weaken defences in Part 2

    # Build the plain HTTP server, then let your code secure it. 
    # After this, the server is ready to accept protected connections.
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd = setup_server_security(httpd, args.host)
    print(f"[server] listening on {args.host}:{args.port}" + (" (INSECURE MODE)" if INSECURE else ""),
          flush=True)
    # Serve requests forever, until Ctrl-C.
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] shutting down")


if __name__ == "__main__":
    main()
