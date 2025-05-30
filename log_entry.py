"""
Full Name: Omid Farahmand
Description: Operations for logging, including device invitation, acceptance, revocation, and photo uploads
have been defined. It make sure to have secure encoding and decoding of log data to keeps its integrity. Also
operations from assignment 1 have been used here as it was mentioned in the description.

"""

import typing as t
from dataclasses import dataclass
from enum import auto, unique, IntEnum

import common.crypto as crypto
import common.types as types
import common.codec as codec
import common.errors as errors

_T = t.TypeVar("_T", bound="LogData")


@dataclass
class LogData:
    pass

    def encode(self) -> bytes:
        return codec.encode([])

    @classmethod
    def decode(cls: _T) -> _T:
        return LogData()

@dataclass
class RegisterLogData(LogData):
    public_key: bytes #store public key for registering 

    def encode(self) -> bytes: #encode public key into bytes
        return codec.encode([self.public_key])

    @classmethod
    # decode bytes into RegisterLogData
    def decode(cls, data: bytes) -> "RegisterLogData":
        (public_key,) = codec.decode(data)
        return cls(public_key)

@dataclass
class PutPhotoLogData(LogData):
    photo_id: int #identifier for photo
    device_public_key: bytes # public key for device uploading photo

    def encode(self):
        #encode photo id and device public key 
        return codec.encode([self.photo_id, self.device_public_key])

    @classmethod
    def decode(cls, data: bytes) -> "PutPhotoLogData":
        # decode bytes to PutPhotoLogData
        (photo_id, device_public_key) = codec.decode(data)
        return cls(photo_id, device_public_key)

@unique
class OperationCode(IntEnum):
    REGISTER = auto()
    PUT_PHOTO = auto()
    INVITE_DEVICE = auto() # inviting a new device
    ACCEPT_INVITE = auto() # accepting a deivce inviation
    REVOKE_DEVICE = auto() # revoking a device access


class LogEntry:
    def __init__(
            # local varaibles
        self,
        version: int,
        opcode: int,
        prev_hmac: bytes,
        this_hmac: bytes,
        data: bytes,
    ) -> None:
        """
        Generates a new log entry with the given data
        """
 
        # initializing the log entries with its required fields like A1
        self.version = version
        self.opcode = opcode.value
        self.prev_hmac = prev_hmac
        self.this_hmac = this_hmac
        self.data = data

    def __str__(self) -> str:
             return f"LogEntry(opcode={OperationCode(self.opcode)}, data={self.data})"

    def encode(self) -> bytes:
        """
        Encode this log entry and the contained data, and return
        a bytestring that represents the whole thing.
        """
        result = codec.encode(
            [
                self.version, # version
                self.opcode,  # operation
                self.prev_hmac, # previos HMAC 
                self.this_hmac, # Current HMAC
                self.data,      # data
            ]
        )
        return result

    @staticmethod
    def decode(data: bytes) -> "LogEntry":
        """
        Decode this log entry and the contained data
        """
        # From Assignment 1 code
        decoded = codec.decode(data)
        # ensure the correct structure
        if not isinstance(decoded, list) or len(decoded) != 5:
            raise errors.MalformedEncodingError("LogEntry decode mismatch")
        version, opcode_int, prev_hmac, this_hmac, data = decoded

        # check type validation
        if not isinstance(version, int):
            raise errors.MalformedEncodingError("invalid version types")
        
        if not isinstance(opcode_int, int):
            raise errors.MalformedEncodingError("invalid opcode types")
        
        if not (isinstance(prev_hmac, bytes) and isinstance(this_hmac, bytes) and isinstance(data, bytes)):
            raise errors.MalformedEncodingError("invalid hash types")
       
        # Validate and convert opcode to OperationCode
        try:
            opcode = OperationCode(opcode_int)
        except ValueError:
            raise errors.MalformedEncodingError(f"invalid opcode: {opcode_int}")

        return LogEntry(version, opcode, prev_hmac, this_hmac, data)

    def data_hash(self) -> bytes:
        return crypto.data_hash(self.encode())


@dataclass
class InviteDeviceLogData(LogData):
    device_public_key: bytes # public key for invited device

    def encode(self):
         # encode device public key
        return codec.encode([self.device_public_key])

    @classmethod
    def decode(cls, data: bytes) -> "InviteDeviceLogData":
        # decode device public key
        device_public_key, = codec.decode(data) 
        # return instance with decode key
        return cls(device_public_key) 


@dataclass
class AcceptInviteLogData(LogData):
 # public key of devices sent the invitation and accepted it
    inviter_public_key: bytes 
    accepted_device_public_key: bytes 

    def encode(self):
        # encode both public key
        return codec.encode([self.inviter_public_key, self.accepted_device_public_key]) 

    @classmethod
    def decode(cls, data: bytes) -> "AcceptInviteLogData":
        # decode both public key
        inviter_public_key, accepted_device_public_key = codec.decode(data)
        # return instance with decode keys
        return cls(inviter_public_key, accepted_device_public_key)

@dataclass
class RevokeDeviceLogData(LogData):
    # public key of devices initiating revocation and being revoked
    revoker_public_key: bytes
    device_public_key: bytes

    def encode(self):
        # encode both public keys
        return codec.encode([self.revoker_public_key, self.device_public_key])

    @classmethod
    def decode(cls, data: bytes) -> "RevokeDeviceLogData":
        # decode both public keys
        revoker_public_key, device_public_key = codec.decode(data)
        # return new instance with decoded key
        return cls(revoker_public_key, device_public_key)
