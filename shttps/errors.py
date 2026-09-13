class SHTTPSError(Exception):
    pass

class ProtocolError(SHTTPSError):
    pass

class SecurityError(SHTTPSError):
    pass

class ReplayError(SecurityError):
    pass

class CompressionError(SHTTPSError):
    pass

class ProviderUnavailable(SecurityError):
    pass
