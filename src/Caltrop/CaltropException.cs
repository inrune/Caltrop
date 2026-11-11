using System.Security.Cryptography;

namespace CaltropSecurity;

/// <summary>Why a Caltrop operation failed. Read it from <see cref="CaltropException.ErrorCode"/>.</summary>
public enum CaltropErrorCode
{
    /// <summary>No specific reason was recorded.</summary>
    Unspecified = 0,

    /// <summary>The input is not valid Caltrop data: bad encoding, too short, or a damaged header.</summary>
    InvalidFormat,

    /// <summary>The data was made by a newer version of Caltrop than this one.</summary>
    UnsupportedVersion,

    /// <summary>
    /// The data is real Caltrop data but of a different kind than the method expects, for example a
    /// password-encrypted message passed to <c>Caltrop.Decrypt</c>. The exception message names the right method.
    /// </summary>
    WrongDataType,

    /// <summary>The data was encrypted for (or signed by) a different key than the one(s) supplied.</summary>
    KeyMismatch,

    /// <summary>Authentication failed: the data was modified or truncated, or the key or password is wrong.</summary>
    AuthenticationFailed,

    /// <summary>The token is genuine but has expired.</summary>
    TokenExpired,

    /// <summary>A key string could not be parsed or failed its integrity check.</summary>
    InvalidKey,
}

/// <summary>
/// Thrown when Caltrop cannot complete an operation, most often because data was tampered with or the wrong key
/// was used. Check <see cref="ErrorCode"/> to see why.
/// </summary>
/// <remarks>
/// Derives from <see cref="CryptographicException"/>, so existing <c>catch (CryptographicException)</c> blocks
/// also catch it. Errors caused by your own code (a <see langword="null"/> argument, an out-of-range length) are
/// reported with the usual <see cref="ArgumentException"/> family instead.
/// </remarks>
public sealed class CaltropException : CryptographicException
{
    /// <summary>Creates an exception with a default message.</summary>
    public CaltropException()
        : this(CaltropErrorCode.Unspecified, "A Caltrop operation failed.")
    {
    }

    /// <summary>Creates an exception with the given message.</summary>
    /// <param name="message">What went wrong.</param>
    public CaltropException(string message)
        : this(CaltropErrorCode.Unspecified, message)
    {
    }

    /// <summary>Creates an exception with the given message and inner exception.</summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The exception that caused this one.</param>
    public CaltropException(string message, Exception innerException)
        : this(CaltropErrorCode.Unspecified, message, innerException)
    {
    }

    /// <summary>Creates an exception with an error code and message.</summary>
    /// <param name="errorCode">Why the operation failed.</param>
    /// <param name="message">What went wrong.</param>
    public CaltropException(CaltropErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>Creates an exception with an error code, message and inner exception.</summary>
    /// <param name="errorCode">Why the operation failed.</param>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The exception that caused this one.</param>
    public CaltropException(CaltropErrorCode errorCode, string message, Exception? innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }

    /// <summary>Why the operation failed.</summary>
    public CaltropErrorCode ErrorCode { get; }
}
