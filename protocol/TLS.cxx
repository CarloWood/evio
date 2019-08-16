#include "sys.h"
#include "TLS.h"
#include "matrixssl/matrixsslApi.h"
#ifdef CWDEBUG
#include "matrixssl/matrixssllib.h"
#include "testkeys/RSA/2048_RSA.h"
#include "testkeys/RSA/2048_RSA_KEY.h"
#include "testkeys/RSA/ALL_RSA_CAS.h"
#endif
#include "utils/debug_ostream_operators.h"
#include <libcwd/buf2str.h>
#include <alloca.h>

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
channel_ct tls("TLS");
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {
namespace protocol {

struct matrixssl_error_code
{
  int32 mCode;

  matrixssl_error_code(int32 code) : mCode(code) { }
  operator int32() const { return mCode; }
};

std::error_code make_error_code(matrixssl_error_code);

std::ostream& operator<<(std::ostream& os, matrixssl_error_code code)
{
  return os << make_error_code(code).category().message(code);
}

} // namespace protocol
} // namespace evio

// Register evio::matrixssl_error_code as valid error code.
namespace std {

template<> struct is_error_code_enum<evio::protocol::matrixssl_error_code> : true_type { };

} // namespace std

namespace evio {
namespace protocol {

std::once_flag TLS::s_flag;

namespace {

sslKeys_t* s_keys;

// Signature algorithms that we are willing to support.
// See the sigalg* macros in matrixssl/crypto/cryptolib.h for a complete list.
uint16_t const sigalgs[] = {
#ifdef USE_ECC
    sigalg_ecdsa_secp256r1_sha256,
# ifdef USE_SECP384R1
    sigalg_ecdsa_secp384r1_sha384,
# endif
# ifdef USE_SECP521R1
    sigalg_ecdsa_secp521r1_sha512,
# endif
#endif // USE_ECC
#ifdef USE_RSA
# ifdef USE_PKCS1_PSS
    sigalg_rsa_pss_rsae_sha256,
#   ifdef USE_SHA384
    sigalg_rsa_pss_rsae_sha384,
#   endif
# endif // USE_RSA
    sigalg_rsa_pkcs1_sha256,
#endif
    0
};
constexpr int32_t sigalgs_len = sizeof(sigalgs) / sizeof(sigalgs[0]) - 1; // -1: remove the trailing 0.

// Ciphersuites that we are willing to support.
// See matrixssl/matrixssl/matrixsslApiCipher.h for a complete list.
psCipher16_t const ciphersuites[] = {
#ifdef USE_TLS_1_3
    TLS_AES_128_GCM_SHA256,
#endif
#ifdef USE_ECC
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
#endif
#ifdef USE_RSA
# ifdef USE_ECC
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
# endif
    TLS_RSA_WITH_AES_128_GCM_SHA256,
#endif // USE_RSA
    0
};
constexpr int32_t ciphersuites_len = sizeof(ciphersuites) / sizeof(ciphersuites[0]) - 1;

// The protocol versions that we're willing to support.
// See matrixssl/matrixssl/matrixsslApiVer.h for all possibilities.
psProtocolVersion_t const versions[] =
{
# ifdef USE_TLS_1_3
    v_tls_1_3,
# endif
# ifdef USE_TLS_1_2
    v_tls_1_2,
# endif
    0
};
constexpr int32_t versions_len = sizeof(versions) / sizeof(versions[0]) - 1;

} // namespace

#ifdef CWDEBUG
std::ostream& operator<<(std::ostream& os, ssl_t& session)
{
  return os << static_cast<FileDescriptor*>(session.userPtr);
}
#endif

//inline
auto const TLS::session() const
{
  return static_cast<ssl_t*>(m_session);
}

//inline
auto const TLS::session_opts() const
{
  return static_cast<sslSessOpts_t*>(m_session_opts);
}

//inline
auto const TLS::session_id() const
{
  return static_cast<sslSessionId_t*>(m_session_id);
}

void TLS::global_tls_initialization()
{
  DoutEntering(dc::tls|dc::notice, "evio::protocol::TLS::global_tls_initialization()");

  Dout(dc::tls|continued_cf, "matrixSslOpenWithConfig(\"" << MATRIXSSL_CONFIG << "\") = ");
  matrixssl_error_code ret = matrixSslOpen();
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslOpen");

  ret = matrixSslNewKeys(&s_keys, NULL);
  if (ret < 0)
  {
    s_keys = nullptr;
    THROW_FALERTC(ret, "matrixSslNewKeys");
  }

  ret = matrixSslLoadRsaKeys(s_keys, NULL, NULL, NULL, "/etc/ssl/certs/ca-certificates.crt");
  if (ret < 0)
  {
    matrixSslDeleteKeys(s_keys);
    s_keys = nullptr;
    THROW_FALERTC(ret, "matrixSslLoadRsaKeys");
  }
}

void TLS::global_tls_deinitialization()
{
  DoutEntering(dc::tls|dc::notice, "evio::protocol::TLS::global_tls_deinitialization()");

  if (s_keys)
  {
    matrixSslDeleteKeys(s_keys);
    s_keys = nullptr;
  }

  matrixSslClose();
}

TLS::TLS() : m_session(nullptr), m_session_opts(nullptr), m_session_id(nullptr)
{
  DoutEntering(dc::tls, "TLS::TLS() [" << this << "]");
  std::call_once(s_flag, global_tls_initialization);
}

TLS::~TLS()
{
  DoutEntering(dc::tls, "TLS::~TLS()");
  matrixSslDeleteSession(session());
  free(m_session_opts);
}

// Certificate callback. See section 6 in the API manual for details.
static int32_t certCb(ssl_t* UNUSED_ARG(ssl), psX509Cert_t* UNUSED_ARG(cert), int32_t alert)
{
  // No extra checks of our own; simply accept the result of MatrixSSL's internal certificate validation.
  return alert;
}

void TLS::session_init(char const* http_server_name)
{
  DoutEntering(dc::tls, "TLS::session_init(\"" << http_server_name << "\")");
  // Only call session_init() once.
  ASSERT(!m_session_opts);
  m_session_opts = calloc(sizeof(sslSessOpts_t), 1);
  session_opts()->userPtr = static_cast<FileDescriptor*>(m_output_device.get());

  // Set supported protocol versions.
  matrixssl_error_code ret = matrixSslSessOptsSetClientTlsVersions(session_opts(), versions, versions_len);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslSessOptsSetClientTlsVersions");

#ifdef USE_ECC
  // Set supported ECC curves for signatures and key exchange The RoT Edition only supports the P-256, P-384 and P-521 curves.
  session_opts()->ecFlags = IS_SECP256R1;
#ifdef USE_SECP384R1
  session_opts()->ecFlags |= IS_SECP384R1;
#endif
#ifdef USE_SECP521R1
  session_opts()->ecFlags |= IS_SECP521R1;
#endif
#endif // USE_ECC

  matrixssl_error_code ret = matrixSslNewSessionId(reinterpret_cast<sslSessionId_t**>(&m_session_id), NULL);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslNewSessionId");

  // Set supported signature algorithms.
  ret = matrixSslSessOptsSetSigAlgs(session_opts(), sigalgs, sigalgs_len);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslSessOptsSetSigAlgs");

  ret = matrixSslNewClientSession(
      reinterpret_cast<ssl_t**>(&m_session),
      s_keys,
      session_id(),
      ciphersuites,
      ciphersuites_len,
      certCb,
      http_server_name,
      NULL,
      NULL,
      session_opts());
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslNewClientSession");
}

int32_t TLS::matrixSslGetOutdata(char** buf_ptr)
{
  matrixssl_error_code ret = ::matrixSslGetOutdata(session(), reinterpret_cast<unsigned char**>(buf_ptr));
  if (AI_UNLIKELY(ret < 0))
    THROW_FALERTC(ret, "matrixSslGetOutdata");
  return ret;
}

TLS::data_result_type TLS::matrixSslSentData(ssize_t wlen)
{
  matrixssl_error_code ret = ::matrixSslSentData(session(), wlen);
  Dout(dc::tls, "matrixSslSentData({" << *session() << "}, " << wlen << ") = " << ret);

  if (AI_UNLIKELY(ret < 0))
    THROW_FALERTC(ret, "matrixSslSentData");

  if (ret == MATRIXSSL_SUCCESS)
    return SUCCESS;	                // Success. No pending data remaining.

  if (ret == MATRIXSSL_HANDSHAKE_COMPLETE)
    return HANDSHAKE_COMPLETE;          // All done.

  if (AI_UNLIKELY(ret == MATRIXSSL_REQUEST_CLOSE))
    return REQUEST_CLOSE;               // All done.

  ASSERT(ret == MATRIXSSL_REQUEST_SEND);
  return REQUEST_SEND;                  // There is more to send.
}

int32_t TLS::matrixSslGetReadbuf(char** buf_ptr)
{
  matrixssl_error_code ret = ::matrixSslGetReadbuf(session(), reinterpret_cast<unsigned char**>(buf_ptr));
  if (AI_UNLIKELY(ret < 0))
    THROW_FALERTC(ret, "matrixSslGetReadbuf");
  return ret;
}

TLS::data_result_type TLS::matrixSslReceivedData(ssize_t rlen, char** buf_ptr, uint32_t* buf_len_ptr)
{
  matrixssl_error_code ret = ::matrixSslReceivedData(session(), rlen, reinterpret_cast<unsigned char**>(buf_ptr), buf_len_ptr);
  Dout(dc::tls, "matrixSslReceivedData({" << *session() << "}, " << rlen << ", buf_ptr, buf_len_ptr) = " << ret);

  if (AI_UNLIKELY(ret < 0))
    THROW_FALERTC(ret, "matrixSslReceivedData");

  switch (ret)
  {
    case PS_SUCCESS:
      return SUCCESS;

    case MATRIXSSL_REQUEST_SEND:
      return REQUEST_SEND;

    case MATRIXSSL_REQUEST_RECV:
      return REQUEST_RECV;

    case MATRIXSSL_HANDSHAKE_COMPLETE:
      return HANDSHAKE_COMPLETE;

    case MATRIXSSL_RECEIVED_ALERT:
      ASSERT(*buf_len_ptr == 2);
      return ((*buf_ptr)[0] == SSL_ALERT_LEVEL_WARNING) ? RECEIVED_ALERT_WARNING : RECEIVED_ALERT_FATAL;

    case MATRIXSSL_APP_DATA:
      return APP_DATA;
  }
  ASSERT(ret == MATRIXSSL_APP_DATA_COMPRESSED);
  return APP_DATA_COMPRESSED;
}

TLS::data_result_type TLS::matrixSslProcessedData(char** buf_ptr, uint32_t* buf_len_ptr)
{
  matrixssl_error_code ret = ::matrixSslProcessedData(session(), reinterpret_cast<unsigned char**>(buf_ptr), buf_len_ptr);
  Dout(dc::tls, "matrixSslReceivedData({" << *session() << "}, buf_ptr, buf_len_ptr) = " << ret);

  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslProcessedData");

  switch (ret)
  {
    case PS_SUCCESS:
      return SUCCESS;

    case MATRIXSSL_APP_DATA:
      return APP_DATA;

    case MATRIXSSL_REQUEST_SEND:
      return REQUEST_SEND;

    case MATRIXSSL_REQUEST_RECV:
      return REQUEST_RECV;
  }
  ASSERT(ret == MATRIXSSL_RECEIVED_ALERT);
  ASSERT(*buf_len_ptr == 2);
  return ((*buf_ptr)[0] == SSL_ALERT_LEVEL_WARNING) ? RECEIVED_ALERT_WARNING : RECEIVED_ALERT_FATAL;
}

//============================================================================
// Error code handling.
// See https://akrzemi1.wordpress.com/2017/07/12/your-own-error-code/

//----------------------------------------------------------------------------
// evio error category

namespace {

struct ErrorCategory : std::error_category
{
  char const* name() const noexcept override;
  std::string message(int ev) const override;
};

char const* ErrorCategory::name() const noexcept
{
  return "evio";
}

std::string ErrorCategory::message(int ev) const
{
  switch (static_cast<error_codes>(ev))
  {
    default:
      return "GNUTLS ErrorCategory::message (unrecognized error)";
  }
}

ErrorCategory const theErrorCategory { };

} // namespace

std::error_code make_error_code(error_codes code)
{
  return std::error_code(static_cast<int>(code), theErrorCategory);
}

//----------------------------------------------------------------------------
// matrixssl error codes (as returned by matrixSslOpen, matrixSslNewKeys, matrixSslLoadRsaKeys, etc)

namespace {

struct MatrixSSLErrorCategory : std::error_category
{
  char const* name() const noexcept override;
  std::string message(int32 ev) const override;
};

char const* MatrixSSLErrorCategory::name() const noexcept
{
  return "matrixssl";
}

std::string MatrixSSLErrorCategory::message(int32 ev) const
{
  switch (ev)
  {
    // core API errors.
    AI_CASE_RETURN(PS_SUCCESS);
    AI_CASE_RETURN(PS_FAILURE);
    AI_CASE_RETURN(PS_ARG_FAIL);
    AI_CASE_RETURN(PS_PLATFORM_FAIL);
    AI_CASE_RETURN(PS_MEM_FAIL);
    AI_CASE_RETURN(PS_LIMIT_FAIL);
    AI_CASE_RETURN(PS_UNSUPPORTED_FAIL);
    AI_CASE_RETURN(PS_DISABLED_FEATURE_FAIL);
    AI_CASE_RETURN(PS_PROTOCOL_FAIL);
    AI_CASE_RETURN(PS_TIMEOUT_FAIL);
    AI_CASE_RETURN(PS_INTERRUPT_FAIL);
    AI_CASE_RETURN(PS_PENDING);
    AI_CASE_RETURN(PS_EAGAIN);
    AI_CASE_RETURN(PS_OUTPUT_LENGTH);
    AI_CASE_RETURN(PS_HOSTNAME_RESOLUTION);
    AI_CASE_RETURN(PS_CONNECT);
    AI_CASE_RETURN(PS_INSECURE_PROTOCOL);
    AI_CASE_RETURN(PS_VERIFICATION_FAILED);

    // crypto API errors.
    AI_CASE_RETURN(PS_PARSE_FAIL);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL_BC);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL_DN);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL_SIG);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL_REVOKED);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL_EXTENSION);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL_PATH_LEN);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL_AUTHKEY);
    AI_CASE_RETURN(PS_SIGNATURE_MISMATCH);
    AI_CASE_RETURN(PS_AUTH_FAIL);
    AI_CASE_RETURN(PS_MESSAGE_UNSUPPORTED);
    AI_CASE_RETURN(PS_VERSION_UNSUPPORTED);
    AI_CASE_RETURN(PS_SELFTEST_FAILED);
  }
  return "Unknown error " + std::to_string(ev);
}

MatrixSSLErrorCategory const theMatrixSSLErrorCategory { };

} // namespace

std::error_code make_error_code(matrixssl_error_code code)
{
  return std::error_code(static_cast<int32>(code), theMatrixSSLErrorCategory);
}

} // namespace protocol
} // namespace evio
