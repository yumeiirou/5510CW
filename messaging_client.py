"""
messaging_client.py - SKELETON

A command-line messaging client. Each user runs their own copy, with their
own state file holding their keys and anything else the client must remember.

HOW THIS SKELETON WORKS
-----------------------
The user interface, the background polling thread, saving
state, and sending HTTP requests is provided and works. The security-critical
methods are not: each one raises NotImplementedError, so the client will not
run until you have written them. Each method's docstring says what it must
achieve. It is up to you how to achieve each goal.

Sections are marked as follows:

  PROVIDED - DO NOT MODIFY   The user interface and polling loop. The
                             functionality test script reads the output of
                             these functions. Changing them may cause the
                             test to fail.
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
       -> Complete check_registration (server); registration on the client-side happens in create_identity and the provided register function

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

This flow covers sending a first message. Your code must also handle
receiving messages, offline delivery, and continuing after a restart.

In this script, you must modify the following sections of code (described in the protocol flow above):
    - Add imports
    - Define URL scheme
    - create_identity function
    - load_keys function
    - server_options function
    - auth_headers function
    - verify_contact_keys function
    - agree_key function
    - send_message function
    - handle_envelope function
    - unprotect_message function

You may also add new methods, attributes and helper functions if you wish.

Command-line arguments (DO NOT rename or remove; you may add new ones):
  --host      server hostname (default: localhost)
  --port      server port (default: 8443)
  --state     file holding this user's state (required)
  --name      username (required the first time a state file is created)
  --insecure  run with security measures weakened, for Part 2
Any files your client creates or reads must be in the current working
directory, and the client must not ask the user for any input at start-up.

INSECURE MODE (Part 2)
----------------------
When the client is started with --insecure, self.insecure is True in every
method. Use it to disable or weaken the specific defences your Part 2 attacks
target, for example:

    if not self.insecure:
        ...verify the sender's signature...

Everything else must keep working in insecure mode. If insecure mode changes
how the client and server talk to each other (for example, dropping TLS),
start BOTH with --insecure. The server URL is built from URL_SCHEME in
__init__, so change it there if your insecure mode needs a different scheme.
Document exactly what insecure mode changes in your README.
"""

import argparse
import base64
import json
import os
import sys
import threading
import requests

# ===========================================================================
# TODO: Add any imports you need here.
# You may use any standard Python libraries.
# You must use cryptography.io for all cryptographic functions.
# Your implementation must work on SCC machines.
# ===========================================================================


POLL_INTERVAL = 1.0   # seconds between mailbox checks


# ===========================================================================
# TODO: define the URL scheme the client uses to reach the server.
# "http" is a plain, unprotected connection and does NOT meet SR1.
# Change this to match the secure channel your server provides in
# setup_server_security.
# ===========================================================================

URL_SCHEME = "http"



# ===========================================================================
# PROVIDED - MAY MODIFY: helpers (identical to those in the server)
# Add any additional helper functions you need here.
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
    """
    out = bytearray()
    for item in (label, *fields):
        if isinstance(item, str):
            item = item.encode("utf-8")
        out += len(item).to_bytes(4, "big") + item
    return bytes(out)


class SecurityError(Exception):
    """Raise this whenever a security check fails."""


class ServerError(Exception):
    """Raised by _request when the server returns an error."""

    def __init__(self, status: int, message: str):
        super().__init__(f"server returned {status}: {message}")
        self.status = status




# ===========================================================================
# The client
# ===========================================================================


class MessagingClient:

    # ----------------------------------------------------------------------
    # PROVIDED - MAY MODIFY: set-up client and create self.state
    # ----------------------------------------------------------------------

    def __init__(self, host: str, port: int, state_path: str, name: str = None,
                 insecure: bool = False):
        """Set up a client object. You do not call this yourself. Instead, Python runs
        it automatically when main creates the client with
        MessagingClient(...). It is the entry point into your code.

        What it does:
        - Stores the connection details (self.server_url is built from
          URL_SCHEME).
        - Decides whether this is a new user or a returning one, by checking
          whether the state file already exists:
            * New user (no state file): creates a fresh self.state and calls
              your create_identity(name) to generate the user's keys and ID,
              then saves the state file.
            * Returning user (state file exists): loads the saved state from
              the file and calls your load_keys() to rebuild the key objects.
   
        self.state is a dictionary holding everything the client remembers
        between runs. It is saved to the state file as JSON by save_state, so
        store only JSON-friendly values in it (use b64e for bytes). self.lock
        guards self.state, because the background polling thread and the
        command loop both use it.
        """
        self.server_url = f"{URL_SCHEME}://{host}:{port}"
        self.state_path = state_path
        self.insecure = insecure
        self.lock = threading.RLock()
        self.http = requests.Session()

        if os.path.exists(state_path):
            with open(state_path) as f:
                self.state = json.load(f)
            self.load_keys()
        else:
            if not name:
                raise ValueError("--name is required the first time a state file is created")
            self.state = {"name": name, "contacts": {}}
            self.create_identity(name)
            self.save_state()

    @property
    def client_id(self) -> str:
        """Your own client ID, short for self.state["client_id"]. Because it is
        a @property, use it as self.client_id (no brackets)."""
        return self.state["client_id"]

    def public_info(self) -> dict:
        """Return the public information stored by your create_identity function, 
        to send to the server. This is whatever other users need to communicate securely
        with the client; it must contain only public values, never a private key."""
        return self.state["public_info"]

    def save_state(self) -> None:
        """Save self.state to the state file, so it survives a restart. Call
        this after changing anything in self.state that must be remembered,
        such as a newly agreed key. (It writes to a temporary file and renames,
        so a crash cannot leave the file half-written.)"""
        with self.lock:
            tmp = self.state_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.state, f)
            os.replace(tmp, self.state_path)

    def _request(self, method: str, path: str, body: dict = None, authenticated: bool = True) -> dict:
        """Send a request to the server and return its JSON reply. This is how
        all your client-server messages are sent (/register, /lookup, /send,
        /receive). It calls your auth_headers function to prove who you are (unless
        authenticated=False, used for registration) and server_options to
        protect the connection. Raises ServerError if the server replies with
        an error."""
        data = json.dumps(body).encode("utf-8") if body is not None else b""
        headers = {"Content-Type": "application/json"} if data else {}
        if authenticated:
            headers.update(self.auth_headers(method, path, data))
        resp = self.http.request(method, self.server_url + path, data=data or None, headers=headers,
                                 timeout=10, **self.server_options())
        try:
            data = resp.json()
        except ValueError:
            data = {"error": resp.text[:200]}
        if resp.status_code != 200:
            raise ServerError(resp.status_code, data.get("error", "unknown error"))
        return data

    # ----------------------------------------------------------------------
    # TODO: Create the client's long-term keys and ID in function create_identity
    # This is necessary to complete protocol flow step 1. 
    # You must also complete a function load_keys, which will convert stored keys
    # back into a key object. 
    # ----------------------------------------------------------------------

    def create_identity(self, name: str) -> None:
        # 1. Generate this user's long-term key pair(s).
        # <your key generation here>

        # 2. Store everything in self.state as JSON-friendly values.
        #    Private keys are saved as base64 text with b64e(...) and rebuilt
        #    by load_keys. 
        # public_info holds ONLY public values: it is sent to the server and to other users.
        
        self.state.update({
            "identity_priv": "",      # b64e(...) of each long-term private key
            "public_info": {},        # the public values others need (public keys, etc.)
            "peers": {},              # a dictionary storing the verified public information of other peers you have connected to
            "keys": {},               # a dictionary storing the shared key you have agreed with each peer (as b64e text)
        })

        # 3. Set the client ID: a whitespace-free string you share out of band,
        #    which must never change for this user. Think about how another
        #    user, given this ID, could check that keys claiming to be yours
        #    really are (see verify_contact_keys).
        self.state["client_id"] = ""   # <set this>

        # 4. Rebuild the key objects (and run on every later start too).
        self.load_keys()
    
        raise NotImplementedError("TODO: create_identity")

    def load_keys(self) -> None:
        """
        Rebuild your key objects from the values saved in self.state.

        Keys are saved as base64 text, but signing and key agreement need key
        objects from the cryptography library. This function turns the saved
        text back into those objects. It runs on every start (and once at the
        end of create_identity). Do NOT generate new keys here.
        """
        # 1. Read each saved private key back from self.state (it is base64
        #    text; use b64d(...) to get the bytes).
        # <read your saved key material here>

        # 2. Turn each one back into a key object from the cryptography library
        #    (for example, with a method such as from_private_bytes), and store
        #    it on self so your other methods can use it.
        # self.<your key> = ...

        # 3. If your other methods need the matching public keys handy (for
        #    example to build public_info or to compute the client ID), you can
        #    derive and store those here too.

        raise NotImplementedError("TODO: load_keys")



    # ----------------------------------------------------------------------
    # TODO: Secure the connection to the server in functions server_options and auth_headers.
    # This is necessary to complete protocol flow steps 2 and 3.
    # server_options tells requests how to check it is talking to the genuine server (SR1). 
    # auth_headers proves to the server which user is making each request (SR2). 
    # _request calls both functions for you on every request, so you never call them directly.
    # ----------------------------------------------------------------------

    def server_options(self) -> dict:
        """
        Return extra keyword arguments passed to requests on EVERY request,
        telling it how to check it is talking to the genuine server. Return {}
        if you need none.

        Do NOT turn verification off (e.g. verify=False): the connection would
        still be encrypted, but the client could no longer tell the real server
        from an impostor. 

        # 1. Work out what your client needs to trust the server. 
        #    This is likely to include files or details written by the server to the current working
        #    directory in setup_server_security.

        # 2. Return the option that points requests at it, for example a dict like {"verify": "<the file name>"}. 
        #    Return {} if your design needs nothing extra.
        raise NotImplementedError("TODO: server_options")
        """

    def auth_headers(self, method: str, path: str, body: bytes) -> dict:
        """
        Return the headers to send with every request (every
        request except registration, for example, request to obtain a peer's verified
        public information or to send a message). 
        
        The header must prove to the server which user is making the request, and must work with the server's get_caller.

        You are given the details of the request, so your proof can cover this
        exact request if your design needs it:
          method  "GET" or "POST"
          path    e.g. "/receive"
          body    the exact bytes of the request body (b"" if there is none)
        """

        # 1. Produce whatever proves this request came from you, using your
        #    long-term key(s) loaded in load_keys. Think about what stops
        #    someone replaying a copy of it later.

        # 2. Return it as headers (a dict of strings). Header values must be
        #    strings, so use b64e(...) for any bytes. Include whatever
        #    get_caller needs to identify you and check the proof.
        raise NotImplementedError("TODO: auth_headers")

    # ----------------------------------------------------------------------
    # PROVIDED - MAY MODIFY: connecting
    # ----------------------------------------------------------------------

    def connect(self) -> None:
        """Run once when the client starts. Registers this user with the
        server so others can find them. (Called for you by main.)"""
        self.register()
        self.authenticate()

    def register(self) -> None:
        """Send this user's ID, name and public information to the server, so
        it can be stored in the directory and looked up by others.

        This runs on normal restarts as well as the first start. Sending the
        same registration again is harmless: the server sees it already has
        these details and accepts it. (This also means the user is re-added
        automatically if the server itself has restarted.) Sent with
        authenticated=False, because the server cannot authenticate a user it
        has not registered yet. You should not need to change this."""

        self._request("POST", "/register", {
            "client_id": self.client_id,
            "name": self.state["name"],
            "public_info": self.public_info(),
        }, authenticated=False)

    def authenticate(self) -> None:
        """Optional extra step after registering, if your design needs one
        (for example, a separate login before making other requests). Does
        nothing by default, and most designs do not need it."""


    # ----------------------------------------------------------------------
    # TODO: Talk to other users, in functions verify_contact_keys, agree_key,
    # send_message, handle_envelope and unprotect_message.
    # This is necessary to complete protocol flow steps 4, 5 and 6.
    #
    # When you first message a peer, you:
    #    - obtain their ID out-of-band 
    #    - look them up via the server 
    #    - verify their keys (verify_contact_keys) 
    #    - agree a shared key with them (agree_key)
    
    # You protect and send messages with the shared key (send_message)
    
    # Incoming envelopes arrive through the polling loop:
    #    - handle_envelope decides what each one is
    #    - unprotect_message recovers the text of a message
    
    # Store agreed keys in self.state so they survive a restart. 
    # You may add helper functions in this section.
    # ----------------------------------------------------------------------


    def verify_contact_keys(self, peer_id: str, record: dict) -> dict:
        """
        Check that a record returned by GET /lookup/<peer_id> genuinely belongs
        to peer_id, and return the verified public information. Raise
        SecurityError if any check fails. 

        peer_id was obtained out of band, so it is the one thing here you can
        trust. The record comes from the server, which may be lying. The record
        is {"client_id": ..., "name": ..., "public_info": {...}}. Note the
        server just echoes back the ID you asked for, so checking
        record["client_id"] == peer_id proves nothing.
        """
        # 1. Pull the public information out of the record.

        # 2. Check it really belongs to peer_id. Think about how peer_id relates
        #    to the keys (this is the check you designed in create_identity).
        #    Raise SecurityError if the check fails.

        # 3. Return the verified public information.
        raise NotImplementedError("TODO: verify_contact_keys")


    def agree_key(self, peer_id: str, peer_info: dict) -> bytes:
        """
        Agree a shared symmetric key with peer_id, whose verified public
        information is peer_info (from verify_contact_keys). The server must not
        be able to learn this key. 
        """
        # 1. Use your own long-term key(s) and the peer's public information to
        #    compute a shared secret that only the two of you can compute.

        # 2. Turn that secret into a symmetric key (do not use the raw shared
        #    secret directly as a key; derive a key from it).

        # 3. Store the key in self.state (keyed by peer_id) so you do not have
        #    to repeat this, and so it survives a restart. Then return it.tImplementedError("TODO: agree_key")
        raise NotImplementedError("TODO: agree_key")


    def send_message(self, peer_id: str, text: str) -> None:
        """
        Send text (the message) to peer_id. Called whenever the user types a
        message. Messages of up to 300 characters must work. 
        """
        # 1. If you have no shared key with peer_id yet: look them up
        #    (GET /lookup/<peer_id>), verify their keys (verify_contact_keys),
        #    and agree a key (agree_key).

        # 2. Encrypt and authenticate the text with that key, so only peer_id
        #    can read it and any change is detected. Never reuse a nonce/IV with
        #    the same key, and use an authenticated mode (not ECB, not plain
        #    CBC/CTR).

        # 3. Put it in an envelope (a dict) that includes "from" (your client
        #    ID) and "to" (peer_id), plus whatever the recipient needs to
        #    decrypt it, and send it with POST /send.
        raise NotImplementedError("TODO: send_message")


    def handle_envelope(self, envelope: dict):
        """
        Process one envelope collected from the server. The provided polling
        code calls this once for each incoming envelope.

        Return the message text for a normal message (it is shown to the user),
        or None for anything the user does not need to see. Raise SecurityError
        if the envelope fails a check or is of a type you do not expect (it is
        shown as rejected).
        """
        # 1. Check the envelope is addressed to you ("to" is your client ID).

        # 2. Decide what kind of envelope it is. If your design sends any
        #    key-setup envelopes (see agree_key), handle those here and return
        #    None. You may add a helper function for that.

        # 3. For a normal message, call unprotect_message and return the text.
        raise NotImplementedError("TODO: handle_envelope")

    def unprotect_message(self, envelope: dict) -> str:
        """
        Recover the text from a message envelope. Return the text only if every
        check passes; otherwise raise SecurityError. 
        """
        # 1. Find the shared key for the sender ("from"). If you have no key for
        #    them, this message cannot be for an agreed conversation: raise
        #    SecurityError.

        # 2. Decrypt and check the message with that key. If the authentication
        #    check fails (the message was changed in transit), raise
        #    SecurityError.

        # 3. Return the recovered text.
        raise NotImplementedError("TODO: unprotect_message")

    # ----------------------------------------------------------------------
    # PROVIDED - DO NOT MODIFY: collecting messages
    # ----------------------------------------------------------------------

    def poll_once(self) -> list:
        """Check the server once for new messages and hand each to your
        handle_envelope. You should not need to change this.

        What your handle_envelope returns decides what happens:
          - a string -> shown to the user as a message
          - None     -> nothing shown (e.g. a key-setup envelope you handled)
          - raises SecurityError -> shown as "rejected"

        Runs in the background about once a second, so messages appear without
        the user doing anything. It holds self.lock while calling your code, so
        you do not need to lock inside handle_envelope."""
        events = []
        for envelope in self._request("GET", "/receive")["envelopes"]:
            sender = str(envelope.get("from", "?"))
            try:
                with self.lock:
                    text = self.handle_envelope(envelope)
                if text is not None:
                    events.append({"kind": "message", "from": sender, "text": text})
            except (SecurityError, ServerError, KeyError, ValueError, TypeError) as e:
                events.append({"kind": "rejected", "from": sender, "detail": f"{type(e).__name__}: {e}"})
        return events


# ===========================================================================
# PROVIDED - DO NOT MODIFY: user interface
# This is the command-line interface: how the user types commands and how
# messages are shown. It is provided so you can focus on the security parts.
# The functionality test script reads the exact output of the ui_ functions
# below, so do not change them. You may CALL ui_info and ui_error from your
# own code to show the user a note or an error.
# ===========================================================================


def ui_identity(client_id: str) -> None:
    """Print the user's own client ID (shown at start-up and by /whoami)."""
    print(f"Your client ID: {client_id}", flush=True)


def ui_message(sender_id: str, text: str) -> None:
    """Print a message received from another user."""
    print(f"\n[from {sender_id}] {text}", flush=True)


def ui_rejected(sender_id: str, detail: str) -> None:
    """Print an envelope that failed a security check (shown as rejected)."""
    print(f"\n[rejected from {sender_id}] {detail}", flush=True)


def ui_info(text: str) -> None:
    """Show the user an informational note. You may call this from your code."""
    print(f"* {text}", flush=True)


def ui_error(text: str) -> None:
    """Show the user an error. You may call this from your code."""
    print(f"! {text}", flush=True)


HELP = """Commands:
  /whoami                 show your client ID (share it out of band)
  /add <alias> <ID>       save a contact under a short name
  /contacts               list contacts
  /msg <alias|ID> <text>  send a message
  /help                   show this help
  /quit                   exit"""


def poll_forever(client: MessagingClient, stop: threading.Event) -> None:
    """Background thread: checks for new messages about once a second and
    displays them, so messages appear without the user doing anything. This
    calls your poll_once. Runs until the client quits."""
    while not stop.is_set():
        try:
            for event in client.poll_once():
                if event["kind"] == "message":
                    ui_message(event["from"], event["text"])
                else:
                    ui_rejected(event["from"], event["detail"])
        except Exception as e:
            ui_error(f"polling failed: {e}")
        stop.wait(POLL_INTERVAL)


def resolve(client: MessagingClient, target: str) -> str:
    """Turn a contact alias (from /add) into a client ID. If target is not a
    saved alias, it is assumed to already be a client ID."""
    with client.lock:
        return client.state["contacts"].get(target, target)


def main():
    """Start the client and run the command loop: set up the client, start the
    background message checker, then read and act on the user's commands until
    they quit. Provided; you should not need to change it."""

    parser = argparse.ArgumentParser(description="Messaging client")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--state", required=True, help="file holding this user's state")
    parser.add_argument("--name", help="username (required for a new state file)")
    parser.add_argument("--insecure", action="store_true", help="weaken security (Part 2)")
    args = parser.parse_args()

    try:
        client = MessagingClient(args.host, args.port, args.state, args.name, args.insecure)
        client.connect()
    except Exception as e:
        ui_error(f"could not start: {e}")
        sys.exit(1)

    ui_identity(client.client_id)
    print(HELP, flush=True)

    stop = threading.Event()
    threading.Thread(target=poll_forever, args=(client, stop), daemon=True).start()

    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue
            cmd, _, rest = line.partition(" ")
            try:
                if cmd == "/quit":
                    break
                elif cmd == "/help":
                    print(HELP)
                elif cmd == "/whoami":
                    ui_identity(client.client_id)
                elif cmd == "/add":
                    alias, _, cid = rest.strip().partition(" ")
                    if not alias or not cid.strip():
                        ui_error("usage: /add <alias> <ID>")
                        continue
                    with client.lock:
                        client.state["contacts"][alias] = cid.strip()
                        client.save_state()
                    ui_info(f"added {alias}")
                elif cmd == "/contacts":
                    with client.lock:
                        for alias, cid in client.state["contacts"].items():
                            print(f"  {alias}: {cid}")
                elif cmd == "/msg":
                    target, _, text = rest.strip().partition(" ")
                    if not text:
                        ui_error("usage: /msg <alias|ID> <text>")
                        continue
                    client.send_message(resolve(client, target), text)
                else:
                    ui_error("unknown command, type /help")
            except Exception as e:
                ui_error(f"{type(e).__name__}: {e}")
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        stop.set()


if __name__ == "__main__":
    main()
