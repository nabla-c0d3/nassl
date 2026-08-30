from enum import IntEnum


class OpenSslEchStatusEnum(IntEnum):
    """The outcome of an ECH (Encrypted Client Hello) attempt, as returned by SSL_ech_get1_status().

    The values here must match the SSL_ECH_STATUS_* constants in OpenSSL's <openssl/ech.h>.
    """

    BACKEND = 4  # ECH backend: saw an ech_is_inner
    GREASE_ECH = 3  # GREASE-d and got an ECH in return
    GREASE = 2  # ECH GREASE happened
    SUCCESS = 1  # ECH succeeded
    FAILED = 0  # Some internal or protocol error
    BAD_CALL = -100  # Some in/out arguments were NULL
    NOT_TRIED = -101  # ECH wasn't attempted
    BAD_NAME = -102  # ECH ok but server cert bad
    NOT_CONFIGURED = -103  # ECH wasn't configured
    FAILED_ECH = -105  # Tried, failed, got an ECH retry config, from a good name
    FAILED_ECH_BAD_NAME = -106  # Tried, failed, got an ECH retry config, from a bad name
