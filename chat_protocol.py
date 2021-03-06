from enum import IntEnum

# Size of message components (in bytes)
MSG_TYPE_SIZE = 1
MSG_SOURCE_SIZE = 1
MSG_SIGNATURE_SIZE = 256
class MsgType(IntEnum):
    JOIN      = 0
    INIT      = 1
    LEAVE     = 2
    MSG       = 3
    SECRET    = 4
    CHALLENGE = 5
