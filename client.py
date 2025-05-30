#!/usr/bin/env python3

"""
Full Name: Omid Farahmand
Description: Mutli device synchronizaton device invitation/revocation, and friend photo sharing with HMAC chain is 
implemented in order to make sure to have data integirty and prevent any unathorized access.

"""

import typing as t
import uuid

from server.reference_server import *
# ---- uncomment to run `make test`
# import log_entry
# from log_entry import *
# ----- comment the line below to run `make test`----
from client.log_entry import *


import common.crypto as crypto
import common.types as types
import common.codec as codec
import common.errors as errors
import requests

from ag.common.mock_http import (
    link_client_server,
)  # imported for doctests, unneeded otherwise


@dataclass
class FriendInfo:
    trusted_keys: t.Set[bytes]
    photos: t.List[bytes]
    last_log_number: int

class Client:
    """The client for the photo-sharing application.

    A client can query a remote server for the list of a user's photos
    as well as the photos themselves.  A client can also add photos on
    behalf of that user.

    A client retains data required to authenticate a user's device
    both to a remote server and to other devices.  To authenticate to
    the remote server, the client presents a username and auth_secret,
    while to authenticate to other devices, the client tags
    updates with an authenticator over the history of all updates.  To
    verify the authenticity of an update, clients check the
    authenticator using a shared symmetric key.
    """

    # maps response RPC name to the corresponding type
    RESPONSE_MAPPINGS: t.Dict[str, types.RpcObject] = {
        "RegisterResponse": types.RegisterResponse,
        "LoginResponse": types.LoginResponse,
        "UpdatePublicProfileResponse": types.UpdatePublicProfileResponse,
        "GetFriendPublicProfileResponse": types.GetFriendPublicProfileResponse,
        "PutPhotoResponse": types.PutPhotoResponse,
        "GetPhotoResponse": types.GetPhotoResponse,
        "PushLogEntryResponse": types.PushLogEntryResponse,
        "SynchronizeResponse": types.SynchronizeResponse,
        "SynchronizeFriendResponse": types.SynchronizeFriendResponse,
    }

    def __init__(
        self,
        username: str,
        remote_url: t.Optional[str] = None,
        user_secret: t.Optional[bytes] = None,
    ) -> None:
        """Initialize a client given a username, a
        remote server's URL, and a user secret.

        If no remote URL is provided, "http://localhost:5000" is assumed.

        If no user secret is provided, this constructor generates a
        new one.
        """
        self._remote_url = remote_url if remote_url else "http://localhost:5000"
        self._client_id = str(uuid.uuid4())

        self._username = username
        self._server_session_token = None

        self._user_secret = crypto.UserSecret(user_secret)

        self._auth_secret = self._user_secret.get_auth_secret()
        self._symmetric_auth = crypto.MessageAuthenticationCode(
            self._user_secret.get_symmetric_key()
        )
        
        self._public_profile = types.PublicProfile(username)
        self._public_key_signer = (
            crypto.PublicKeySignature()
        )  # not derived from user secret---every device gets its own key pair

        self._photos: t.List[bytes] = []    # list of photos in put_photo order
        self._last_log_number: int = -1     # A1
        self._next_photo_id: int = 0

        self._intended_photos: t.List[bytes] = []
        self._local_log: t.List[bytes] = []  

        # chain hmac from Assignment 1
        self._last_chain_hmac: bytes = bytes()
        self._registered_key: t.Optional[bytes] = None
        

        # maps usernames to friend state
        self._friends: t.Dict[str, FriendInfo] = {}
       


    def send_rpc(self, request: types.RpcObject) -> types.RpcObject:
        """
        Sends the given RPC object to the server,
        and returns the server's response.

        To do so, does the following:
        - Converts the given RPC object to JSON
        - Sends a POST request to the server's `/rpc` endpoint
            with the RPC JSON as the body
        - Converts the response JSON into the correct RPC object.

        ## DO NOT CHANGE THIS METHOD

        It is overridden for testing, so any changes will be
        overwritten.
        """
        r = requests.post(f"{self._remote_url}/rpc",
                          json=request.as_rpc_dict())
        resp = r.json()
        resp_type = self.RESPONSE_MAPPINGS.get(resp["rpc"], None)
        if resp_type is None:
            raise ValueError(f'Invalid response type "{resp["rpc"]}".')
        resp = resp_type.from_dict(resp["data"])
        return resp
 
    @property
    def username(self) -> str:
        """Get the client's username.

        >>> alice = Client("alice")
        >>> alice.username == "alice"
        True
        """
        return self._username

    @property
    def user_secret(self) -> bytes:
        """Get the client's user secret.

        >>> user_secret = crypto.UserSecret().get_secret()
        >>> alice = Client("alice", user_secret=user_secret)
        >>> alice.user_secret == user_secret
        True
        """
        return self._user_secret.get_secret()

    @property
    def public_key(self) -> bytes:
        """Get the client's public key.
        """
        return bytes(self._public_key_signer.public_key)

    def register(self) -> None:
        """Register this client's username with the server,
        initializing the user's state on the server.

        If the client is already registered, raise a
        UserAlreadyExistsError.

        Otherwise, save the session token returned by the server for
        use in future requests.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)

        >>> alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        >>> alice.register()
        >>> alice.login()
        """
        # log entry parameters 
        version = 0   #starts at 0
        opcode = OperationCode.REGISTER # operation type
        photo_id = 0     # no photo associated with registration
        photo_hash = bytes()   # No photo hash 
        prev_hmac = bytes() # no previous HMAC with start of the chain 
        data = RegisterLogData(self.public_key).encode() #encode the public key

        # Compute the HMAC for the log entry
        this_hmac = self._compute_log_hmac(version, opcode.value, photo_id, photo_hash, prev_hmac)
        # encode the log entry
        entry = LogEntry(version, opcode, prev_hmac, this_hmac, data)
        encoded_entry = entry.encode()

        # request to the server 
        req = types.RegisterRequest(self._client_id, self._username, self._auth_secret, encoded_entry)
        resp = self.send_rpc(req)
        # correct response type
        assert isinstance(resp, types.RegisterResponse)
        if resp.error is None:
            # update local state
            self._last_log_number = version
            self._server_session_token = resp.token #store the token
            self._last_chain_hmac = this_hmac   #update the chain
            self._local_log.append(encoded_entry) #append to local log

            #register key
            if self._registered_key is None:
                self._registered_key = self.public_key
            elif self._registered_key != self.public_key:
                #duplicate
                raise errors.SynchronizationError("Multiple Register")
        
        elif resp.error == types.Errcode.USER_ALREADY_EXISTS:
            raise errors.UserAlreadyExistsError(self._username)
        else:
            raise Exception(resp)

    def login(self) -> None:
        """Try to login with to the server with the username and
        auth_secret.

        On success, save the new session token returned by the server
        for use in future requests.

        Otherwise, if the username and auth_secret combination is
        incorrect, raise a LoginFailedError.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)

        >>> alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        >>> alice.register()
        >>> alice.login()

        >>> not_alice = Client("alice", server)
        >>> link_client_server(not_alice, server)
        >>> not_alice.login()
        Traceback (most recent call last):
                ...
        common.errors.LoginFailedError: failed to log alice in

        See also: Client.register
        """
        req = types.LoginRequest(
            client_id=self._client_id,
            username=self._username,
            auth_secret=self._auth_secret,
        )  
        resp = self.send_rpc(req)
        assert isinstance(resp, types.LoginResponse)
        if resp.error is None:
            self._server_session_token = resp.token
        elif resp.error == types.Errcode.LOGIN_FAILED:
            raise errors.LoginFailedError(self._username)
        else:
            raise Exception(resp)
    
    def _compute_log_hmac( #A1
        self,
        version: int,
        opcode_val: int,
        photo_id: int,
        photo_hash: bytes,
        prev_hmac: bytes,
    ) -> bytes:
     
        "Compute HMAC over (version, opcode, photo_id, photo_hash, prev_hmac)."
        # Encode fields into a standardized format
        data_for_mac = [version, opcode_val, photo_id, photo_hash, prev_hmac]
        encoded = codec.encode(data_for_mac)
        # Generate HMAC with symmetric authentication key
        return self._symmetric_auth.gen_mac(encoded)
    
    def update_public_profile(self, values: t.Dict[str, t.Any]) -> None:
        """Update user public profile with the given fields.
        """
        # TODO (assignment0): Update te local public profile based on the given values and update the server
        raise NotImplementedError

    def get_friend_public_profile(self, friend_username: str) -> types.PublicProfile:
        """Obtain the public profile of another user.
        """
        # TODO (assignment00): Fetch and return the public profile of the user friend_username
        raise NotImplementedError
    
    def list_photos(self) -> t.List[int]:
        """Fetch a list containing the photo id of each photo stored
        by the user.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> photo_blob = b'PHOOT0O'
        >>> alice.put_photo(photo_blob)
        2
        >>> alice.list_photos()
        [0, 1, 2]
        """
        self._synchronize()

        return list(range(self._next_photo_id))
    
    def get_photo(self, photo_id) -> bytes:
        """Get a photo by ID.

        >>> server = ReferenceServer()
        >>> alice = Client("alice")
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> photo_id = alice.put_photo(photo_blob)
        >>> photo_id
        0
        >>> alice._fetch_photo(photo_id)
        b'PHOTOOO'
        >>> alice._fetch_photo(1)
        Traceback (most recent call last):
                ...
        common.errors.PhotoDoesNotExistError: photo with ID 1 does not exist
        """
        self._synchronize()

        if photo_id < 0 or photo_id >= len(self._photos):
            raise errors.PhotoDoesNotExistError(photo_id)
        return self._photos[photo_id]
    
    def _push_log_entry(self, log_entry: LogEntry) -> None:
        """
        Push the given log entry to the server
        """
        encoded_log_entry = log_entry.encode()
        req = types.PushLogEntryRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            encoded_log_entry=encoded_log_entry,
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.PushLogEntryResponse)
        if resp.error:
            raise errors.RpcError
        
    def _fetch_photo(self, photo_id, user: t.Optional[str] = None) -> bytes:
        """Get a photo from the server using the unique PhotoID.

        If `user` is specified, fetches the photo for the given
        user. Otherwise, fetches for this user.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> photo_id = alice.put_photo(photo_blob)
        >>> photo_id
        0
        >>> alice._fetch_photo(photo_id)
        b'PHOTOOO'
        >>> alice._fetch_photo(1)
        Traceback (most recent call last):
                ...
        common.errors.PhotoDoesNotExistError: photo with ID 1 does not exist
        """
        req = types.GetPhotoRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            photo_id=photo_id,
            photo_owner=user or self._username,  # fetch own photo if unspecified
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.GetPhotoResponse)
        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error == types.Errcode.PHOTO_DOES_NOT_EXIST:
            raise errors.PhotoDoesNotExistError(photo_id)
        elif resp.error is not None:
            raise Exception(resp)
        return resp.photo_blob

   
    def put_photo(self, photo_blob: bytes):
        """Append a photo_blob to the server's database.

        On success, this returns the unique photo_id associated with
        the newly-added photo.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> photo_blob = b'PHOTOOO'
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> photo_blob = b'PHOOT0O'
        >>> alice.put_photo(photo_blob)
        2
        """
        self._synchronize()

        photo_id = self._next_photo_id
        
        # log entry parameters
        opcode = OperationCode.PUT_PHOTO 
        version = self._last_log_number + 1 #increment the log version
        prev_hmac = self._last_chain_hmac #HMAC chain 
        photo_hash = crypto.data_hash(photo_blob) #hash for integrity 
       
        # ecnode data (photo id, public key)
        data = PutPhotoLogData(photo_id, self.public_key).encode()

        # compute the HMAC 
        this_hmac = self._compute_log_hmac(version, opcode.value, photo_id, photo_hash, prev_hmac)
        # create and encode log entry 
        entry = LogEntry(version, opcode, prev_hmac, this_hmac, data)
        encoded_entry = entry.encode()

        req = types.PutPhotoRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            encoded_log_entry=encoded_entry,
            photo_blob=photo_blob,
            photo_id=photo_id,
        )

        resp = self.send_rpc(req)
        assert isinstance(resp, types.PutPhotoResponse)
        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error is not None:
            raise Exception(resp)

        self._intended_photos.append(photo_blob)
        self._record_new_photo(encoded_entry, photo_blob)
        return photo_id

    def _record_new_photo(self, encoded_entry: bytes, photo_blob: bytes) -> None:
        """
        Locally record a new photo, store newly uploaded photo in local log
        """
        # decode the encoded log entry
        entry = LogEntry.decode(encoded_entry)

        # update local log and chain HMAC
        self._last_log_number = entry.version
        self._last_chain_hmac = entry.this_hmac

        # store the photo if its log entry
        if entry.opcode == OperationCode.PUT_PHOTO.value:
            self._next_photo_id += 1    
            self._photos.append(photo_blob) 
         # append the log entry
        self._local_log.append(encoded_entry)
 
    def _synchronize(self):
        """Synchronize the client's state against the server.

        On failure, this raises a SynchronizationError.

        >>> server = ReferenceServer()
        >>> alice = Client("alice", server)
        >>> link_client_server(alice, server)
        >>> alice.register()
        >>> user_secret = alice.user_secret
        >>> alicebis = Client("alice", server, user_secret)
        >>> link_client_server(alicebis, server)
        >>> alicebis.login()
        >>> alicebis._synchronize()
        >>> alice.login()
        >>> photo_blob = b'PHOTOOO'
        >>> alice._synchronize()
        >>> alice.put_photo(photo_blob)
        0
        >>> photo_blob = b'PHOOOTO'
        >>> alice.put_photo(photo_blob)
        1
        >>> alicebis.login()
        >>> photo_blob = b'PHOOT0O'
        >>> alicebis._synchronize()
        >>> photo_blob = b'PHOOT0O'
        >>> alicebis.put_photo(photo_blob)
        2
        """
        # First, re-check all local photos.
        for i in range(len(self._photos)):
            fetched_blob = self._fetch_photo(i)
            if fetched_blob != self._photos[i]:
                raise errors.SynchronizationError("Local photo state mismatch")
        
        # Fetch new log entries starting from version _last_log_number + 1.
        req = types.SynchronizeRequest(
            client_id=self._client_id,
            username=self._username,
            token=self._server_session_token,
            min_version_number=self._last_log_number + 1,
        )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.SynchronizeResponse)

        if resp.error == types.Errcode.INVALID_TOKEN:
            raise errors.InvalidTokenError()
        elif resp.error == types.Errcode.VERSION_TOO_HIGH:
            raise errors.SynchronizationError(errors.VersionTooHighError())
        elif resp.error is not None:
            raise Exception(resp)
        
        for encoded in resp.encoded_log_entries:
            if not isinstance(encoded, bytes):  
                raise errors.SynchronizationError("Invalid log entry")
            
            log = LogEntry.decode(encoded)  # if valid

            # Check that version increments by one. MAYBE
            expected_version = self._last_log_number + 1
            if log.version != expected_version:
                raise errors.SynchronizationError("version gap chain")
            
            # check that the prev_hmac matches the chain.
            if log.prev_hmac != self._last_chain_hmac:
                raise errors.SynchronizationError("HMAC mismatch")
    
            # compute expected HMAC based on the log entries
            if log.opcode == OperationCode.REGISTER.value:
                expected_hmac = self._compute_log_hmac(log.version, OperationCode.REGISTER.value, 0, bytes(), log.prev_hmac
                                                       )
            elif log.opcode == OperationCode.PUT_PHOTO.value:
                put_data = PutPhotoLogData.decode(log.data)

                # Fetch the photo to recompute its hash.
                fetched_blob = self._fetch_photo(put_data.photo_id)
                expected_photo_hash = crypto.data_hash(fetched_blob)

                # compute expected HMAC
                expected_hmac = self._compute_log_hmac(
                    log.version, OperationCode.PUT_PHOTO.value, put_data.photo_id, expected_photo_hash, log.prev_hmac)
            elif log.opcode in (OperationCode.INVITE_DEVICE.value,
                                  OperationCode.ACCEPT_INVITE.value,
                                  OperationCode.REVOKE_DEVICE.value):
                # For device, no photo hash is used.
                expected_hmac = self._compute_log_hmac(
                    log.version, log.opcode, 0, bytes(), log.prev_hmac)
            
            else:
                raise errors.SynchronizationError(f"opcode{log.opcode}")
            
            # validate the HMAC againts the log's HMAC
            if expected_hmac != log.this_hmac:
                raise errors.SynchronizationError("HMAC failed")
            
            # Process the entry.
            if log.opcode == OperationCode.REGISTER.value:
                reg_data = RegisterLogData.decode(log.data)
                if self._registered_key is None:
                    self._registered_key = reg_data.public_key
                else:
                    raise errors.SynchronizationError("Multiple register detected")
       
            elif log.opcode == OperationCode.PUT_PHOTO.value:
                put_data = PutPhotoLogData.decode(log.data)
                expected_id = len(self._photos)
                # unexpected photo id 
                if put_data.photo_id != expected_id:
                    if put_data.photo_id < expected_id:

                        fetched_blob = self._fetch_photo(put_data.photo_id)
                        if fetched_blob != self._photos[put_data.photo_id]:
                            raise errors.SynchronizationError("Duplicate photo mismatch")
                        raise errors.SynchronizationError("Duplicate PUT_PHOTO detected")
                    else:
                        raise errors.SynchronizationError("Unexpected photo chain")
               
                # fetch the new photo and verfiy 
                new_blob = self._fetch_photo(put_data.photo_id)   
                if put_data.photo_id < len(self._intended_photos) and self._intended_photos[put_data.photo_id] != new_blob:
                    raise errors.SynchronizationError("Photo blob mismatch new photo")
                # record the new photo 
                self._record_new_photo(encoded, new_blob)
            elif log.opcode in (OperationCode.INVITE_DEVICE.value,
                                  OperationCode.ACCEPT_INVITE.value,
                                  OperationCode.REVOKE_DEVICE.value):
                # update the state for device operations
                self._local_log.append(encoded)
                self._last_log_number = log.version
                self._last_chain_hmac = log.this_hmac
            else:
                raise errors.SynchronizationError(f"opcode {log.opcode}")
            
            # Finalize chain state.
            self._last_log_number = log.version
            self._last_chain_hmac = log.this_hmac
            self._local_log.append(encoded)
    
    def invite_device(self, device_public_key: bytes) -> None:
          # TODO (assignment 2)
        
        # latest log state 
        self._synchronize()
        # log entry details
        new_version = self._last_log_number + 1
        opcode = OperationCode.INVITE_DEVICE
        prev_hmac = self._last_chain_hmac

        data = InviteDeviceLogData(device_public_key).encode()
        # compute the HMAC for verification
        this_hmac = self._compute_log_hmac(
            new_version,
            opcode.value,
            0,
            bytes(),  
            prev_hmac
        )
         # create and encode the log entry       
        entry = LogEntry(new_version, opcode, prev_hmac, this_hmac, data)
        
        # send request to server
        req = types.PushLogEntryRequest(
            self._client_id,
            self._username,
            self._server_session_token,
            entry.encode()
        )
        resp = self.send_rpc(req)
        # hande the reponse errors
        if not isinstance(resp, types.PushLogEntryResponse):
            raise errors.SynchronizationError("response in invite_device")
      
        if resp.error:
            raise errors.RpcError
        # update local state
        self._last_log_number = new_version
        self._local_log.append(entry.encode())
        self._last_chain_hmac = entry.this_hmac

   
    def accept_invite(self, inviter_public_key: bytes) -> None:
        # TODO (assignment 2)

        # latest log state
        self._synchronize()
         # log entry details
        new_version = self._last_log_number + 1
        opcode = OperationCode.ACCEPT_INVITE
        prev_hmac = self._last_chain_hmac

        data = AcceptInviteLogData(inviter_public_key, self.public_key).encode()
         # compute the HMAC for verification
        this_hmac = self._compute_log_hmac(
                    new_version,
                    opcode.value,
                    0,
                    bytes(),  
                    prev_hmac
                )
        # create and encode the log entry       
        entry = LogEntry(new_version, opcode, prev_hmac, this_hmac, data)
         # send request to server
        req = types.PushLogEntryRequest(
                    self._client_id,
                    self._username,
                    self._server_session_token,
                    entry.encode()
                )
        resp = self.send_rpc(req)
        # hanlde reponse errors
        if not isinstance(resp, types.PushLogEntryResponse):
            raise errors.SynchronizationError("response in accept_invite")
        
        if resp.error:
            raise errors.RpcError
        # update local state
        self._last_log_number = new_version
        self._local_log.append(entry.encode())
        self._last_chain_hmac = entry.this_hmac

    def revoke_device(self, device_public_key: bytes) -> None:
        # TODO (assignment 2)
        
         # latest log state
        self._synchronize()
         # log entry details
        new_version = self._last_log_number + 1
        opcode = OperationCode.REVOKE_DEVICE
        prev_hmac = self._last_chain_hmac

        data = RevokeDeviceLogData(self.public_key, device_public_key).encode()
        
         # compute the HMAC for verification
        this_hmac = self._compute_log_hmac(
                        new_version,
                        opcode.value,
                        0,
                        bytes(),  
                        prev_hmac
                    )
      # create and encode the log entry       
        entry = LogEntry(new_version, opcode, prev_hmac, this_hmac, data)
        # send request to server
        req = types.PushLogEntryRequest(
                            self._client_id,
                            self._username,
                            self._server_session_token,
                            entry.encode()
                        )
        resp = self.send_rpc(req)

        # hanlde reponse errors
        if not isinstance(resp, types.PushLogEntryResponse):
            raise errors.SynchronizationError("response in revoke_device")
       
        if resp.error:
            raise errors.RpcError
        # update local state
        self._last_log_number = new_version
        self._local_log.append(entry.encode())
        self._last_chain_hmac = entry.this_hmac

    def add_friend(self, friend_username: str, friend_public_key: bytes) -> None:
            """
            Adds the person with the given username to the local
            friends list, marking the given public key as trusted.

            If the friend already exists, overwrites their public key
            with the provided one.
            """
            self._friends[friend_username] = FriendInfo(
                set([friend_public_key]), [], 0)
    
    def get_friend_photos(self, friend_username) -> t.List[bytes]:
        self._synchronize_friend(friend_username)
        return self._friends[friend_username].photos

    def _synchronize_friend(self, friend_username: str):
        """
        Update the state of the given friend locally
        based on the friend's log in the server.
        """
        if friend_username not in self._friends:
            raise errors.UnknownUserError(friend_username)
        friend_info = self._friends[friend_username]
        req = types.SynchronizeFriendRequest(
            self._client_id, friend_username, 0
            )
        resp = self.send_rpc(req)
        assert isinstance(resp, types.SynchronizeFriendResponse)

        if resp.error == types.Errcode.VERSION_TOO_HIGH:
            raise errors.SynchronizationError(errors.VersionTooHighError())
        elif resp.error is not None:
            raise Exception(resp)
        
        # initializing the variables
        verified_photos = []  
        photo_uploaders = []  
        authorized = set(friend_info.trusted_keys)  
        pending_invites = set()  
        revocations = []  
        revoked_set = set()  
        photo_index = 0  

        friend_registered_key = None
        # process the log entry
        for encoded in resp.encoded_friend_log_entries:
            try:
                log = LogEntry.decode(encoded) #decode the log entry 
            except errors.MalformedEncodingError as e:
                raise errors.SynchronizationError(e)
            
            # handle different log entry types
            if log.opcode == OperationCode.REGISTER.value:
                reg_data = RegisterLogData.decode(log.data)
                if friend_registered_key is None:
                    friend_registered_key = reg_data.public_key
                    authorized.add(reg_data.public_key)
                    
                else:
                    
                    raise errors.SynchronizationError("Multiple REGISTER events friend log")
            elif log.opcode == OperationCode.INVITE_DEVICE.value:
                invite_data = InviteDeviceLogData.decode(log.data)
                pending_invites.add(invite_data.device_public_key)

            #check to see if revoked device to accept invitation or autheticate
            elif log.opcode == OperationCode.ACCEPT_INVITE.value:
                accept_data = AcceptInviteLogData.decode(log.data)
                if accept_data.accepted_device_public_key in revoked_set:
                    raise errors.SynchronizationError("Revoked device")
                
                #device was previously invited 
                if accept_data.accepted_device_public_key not in pending_invites:
                    raise errors.SynchronizationError("accept_invite, no matching invite")
                # update authorization 
                pending_invites.remove(accept_data.accepted_device_public_key)
                authorized.add(accept_data.accepted_device_public_key)

            elif log.opcode == OperationCode.REVOKE_DEVICE.value:
                revoke_data = RevokeDeviceLogData.decode(log.data)

                # authorized devices can revoke
                if revoke_data.revoker_public_key not in authorized:
                    raise errors.SynchronizationError("Invalid revoke")
                
                # revocation event record
                revocations.append((photo_index, revoke_data.revoker_public_key, revoke_data.device_public_key))
                authorized.discard(revoke_data.device_public_key)
                pending_invites.discard(revoke_data.device_public_key)
                revoked_set.add(revoke_data.device_public_key)

            elif log.opcode == OperationCode.PUT_PHOTO.value:
                put_data = PutPhotoLogData.decode(log.data)
                
                # authorized devices can upload photo
                if put_data.device_public_key not in authorized:
                    raise errors.SynchronizationError("Photo uploaded by unauthorized device")
                
                # correct order of photo
                if put_data.photo_id != len(verified_photos):
                    raise errors.SynchronizationError("Photo order tampered in friend log")
                photo_blob = self._fetch_photo(put_data.photo_id, friend_username)
                verified_photos.append(photo_blob)

        # updates and finalize
        friend_info.photos = verified_photos
        friend_info.last_log_number = len(resp.encoded_friend_log_entries)
        friend_info = authorized
        friend_info = photo_uploaders
