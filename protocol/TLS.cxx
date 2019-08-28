#include "sys.h"
#include "TLS.h"
#include "matrixssl/matrixsslApi.h"
#include "matrixssl/matrixssllib.h"
#ifdef CWDEBUG
#include "testkeys/RSA/2048_RSA.h"
#include "testkeys/RSA/2048_RSA_KEY.h"
#include "testkeys/RSA/ALL_RSA_CAS.h"
#include "testkeys/PSK/tls13_psk.h"
#include "utils/debug_ostream_operators.h"
#include <libcwd/buf2str.h>
#endif

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
  // Also support printing positive values as just integers...
  int32 val = code;
  if (val > 0)
    os << val;
  else
    os << make_error_code(code).category().message(code);
  return os;
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

std::string TLS::get_CA_files()
{
  // TODO: Add other standard file paths and directories and support for environment variables
  // like REQUESTS_CA_BUNDLE, SSL_CERT_FILE and SSL_CERT_DIR.
  // See also https://serverfault.com/a/722646.

  // Debian/Ubuntu/Gentoo etc (debian based distributions):
  return "/etc/ssl/certs/ca-certificates.crt";
  // RHEL 6:
  // "/etc/pki/tls/certs/ca-bundle.crt"
  // RHEL 7 / CentOS:
  // "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
  // See also https://techjourney.net/update-add-ca-certificates-bundle-in-redhat-centos/
}

void TLS::global_tls_initialization()
{
  DoutEntering(dc::tls|dc::notice, "evio::protocol::TLS::global_tls_initialization()");

  Dout(dc::tls|continued_cf, "matrixSslOpenWithConfig(\"" << MATRIXSSL_CONFIG << "\") = ");
  matrixssl_error_code ret = matrixSslOpen();
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslOpen");

  Dout(dc::tls|continued_cf, "matrixSslNewKeys(&s_keys, NULL) = ");
  ret = matrixSslNewKeys(&s_keys, NULL);
  Dout(dc::finish, ret);
  if (ret < 0)
  {
    s_keys = nullptr;
    THROW_FALERTC(ret, "matrixSslNewKeys");
  }

  Dout(dc::tls|continued_cf, "matrixSslLoadRsaKeys(s_keys, NULL, NULL, NULL, \"" << get_CA_files() << "\") = ");
  ret = matrixSslLoadRsaKeys(s_keys, NULL, NULL, NULL, get_CA_files().c_str());
  Dout(dc::finish, ret);
  if (ret < 0)
  {
    Dout(dc::tls, "matrixSslDeleteKeys(s_keys)");
    matrixSslDeleteKeys(s_keys);
    s_keys = nullptr;
    THROW_FALERTC(ret, "matrixSslLoadRsaKeys");
  }

#ifdef CWDEBUG
  // Load RSA2048 test key pair.
  unsigned char const* cert_buf = RSA2048;
  int32 cert_buf_len = sizeof(RSA2048);
  unsigned char const* key_buf = RSA2048KEY;
  int32 key_buf_len = sizeof(RSA2048KEY);
  int32 trustedCALen = sizeof(RSACAS);
  unsigned char* trustedCABuf = (unsigned char*)psMalloc(NULL, trustedCALen);
  std::memcpy(trustedCABuf, RSACAS, trustedCALen);

  Dout(dc::tls|continued_cf, "matrixSslLoadRsaKeysMem(s_keys, RSA2048, " << cert_buf_len << ", RSA2048KEY, " << key_buf_len << ", RSACAS, " << trustedCALen << ") = ");
  ret = matrixSslLoadRsaKeysMem(s_keys, cert_buf, cert_buf_len, key_buf, key_buf_len, trustedCABuf, trustedCALen);
  Dout(dc::finish, ret);
  if (ret < 0)
  {
    Dout(dc::tls, "matrixSslDeleteKeys(s_keys)");
    matrixSslDeleteKeys(s_keys);
    s_keys = nullptr;
    THROW_FALERTC(ret, "matrixSslLoadRsaKeys");
  }

  // Load the TLS 1.3 test PSKs.
  Dout(dc::tls|continued_cf, "matrixSslLoadTls13Psk(g_tls13_test_psk_256, " << sizeof(g_tls13_test_psk_256) <<
      ", g_tls13_test_psk_id_sha256, " << sizeof(g_tls13_test_psk_id_sha256) << ", NULL) = ");
  ret = matrixSslLoadTls13Psk(s_keys,
      g_tls13_test_psk_256,
      sizeof(g_tls13_test_psk_256),
      g_tls13_test_psk_id_sha256,
      sizeof(g_tls13_test_psk_id_sha256),
      NULL);
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslLoadTls13Psk");
#endif // CWDEBUG
}

void TLS::global_tls_deinitialization()
{
  DoutEntering(dc::tls|dc::notice, "evio::protocol::TLS::global_tls_deinitialization()");

  if (s_keys)
  {
    Dout(dc::tls, "matrixSslDeleteKeys(s_keys)");
    matrixSslDeleteKeys(s_keys);
    s_keys = nullptr;
  }

  Dout(dc::tls, "matrixSslClose()");
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
  Dout(dc::tls, "matrixSslDeleteSession(" << session() << ")");
  matrixSslDeleteSession(session());
  free(m_session_opts);
}

// Certificate callback. See section 6 in the API manual for details.
static int32_t certCb(ssl_t* UNUSED_ARG(ssl), psX509Cert_t* UNUSED_ARG(cert), int32_t alert)
{
  // No extra checks of our own; simply accept the result of MatrixSSL's internal certificate validation.
  return alert;
}

static int32_t extensionCb(ssl_t* UNUSED_ARG(ssl), uint16_t extType, uint8_t UNUSED_ARG(extLen), void* e)
{
  if (extType == EXT_ALPN)
  {
    unsigned char* c = (unsigned char*)e;
    char proto[128];
    std::memset(proto, 0, sizeof(proto));
    // Two byte proto list len, one byte proto len, then proto.
    c += 2;     // Skip proto list len.
    unsigned short len = *c++;
    if (len >= sizeof(proto))
      return PS_FAILURE;
    std::memcpy(proto, c, len);
    proto[sizeof(proto) - 1] = 0;
    Dout(dc::tls, "Server agreed to use " << buf2str(proto, len));
  }
  return PS_SUCCESS;
}

void TLS::session_init(std::string const& ServerNameIndication)    // SNI
{
  DoutEntering(dc::tls, "TLS::session_init(\"" << ServerNameIndication << "\")");
  // Only call session_init() once.
  ASSERT(!m_session_opts);
  m_session_opts = calloc(sizeof(sslSessOpts_t), 1);
  session_opts()->userPtr = static_cast<FileDescriptor*>(m_output_device.get());

  // Set supported protocol versions.
  Dout(dc::tls|continued_cf, "matrixSslSessOptsSetClientTlsVersions(...) = ");
  matrixssl_error_code ret = matrixSslSessOptsSetClientTlsVersions(session_opts(), versions, versions_len);
  Dout(dc::finish, ret);
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

  Dout(dc::tls|continued_cf, "matrixSslNewSessionId(&m_session_id, NULL) = ");
  ret = matrixSslNewSessionId(reinterpret_cast<sslSessionId_t**>(&m_session_id), NULL);
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslNewSessionId");

  // Set supported signature algorithms.
  Dout(dc::tls|continued_cf, "matrixSslSessOptsSetSigAlgs(session_opts(), sigalgs, sigalgs_len) = ");
  ret = matrixSslSessOptsSetSigAlgs(session_opts(), sigalgs, sigalgs_len);
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslSessOptsSetSigAlgs");

  tlsExtension_t* extension;
  Dout(dc::tls|continued_cf, "matrixSslNewHelloExtension(&extension, NULL) = ");
  ret = matrixSslNewHelloExtension(&extension, NULL);
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslNewHelloExtension");

  unsigned char* ext;
  int32 extLen;
  Dout(dc::tls|continued_cf, "matrixSslCreateSNIext(NULL, \"" << ServerNameIndication << "\", " << ServerNameIndication.length() << ", &ext, &extLen) = ");
  ret = matrixSslCreateSNIext(NULL, ServerNameIndication.c_str(), ServerNameIndication.length(), &ext, &extLen);
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslCreateSNIext");

  Dout(dc::tls|continued_cf, "matrixSslLoadHelloExtension(...) = ");
  ret = matrixSslLoadHelloExtension(extension, ext, extLen, EXT_SNI);
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslLoadHelloExtension");

  psFree(ext, NULL);

#ifdef USE_ALPN
  // Application Layer Protocol Negotiation.
  alpn[0] = (unsigned char *)psMalloc(NULL, Strlen("http/1.0"));
  Memcpy(alpn[0], "http/1.0", Strlen("http/1.0"));
  alpnLen[0] = Strlen("http/1.0");

  alpn[1] = (unsigned char *)psMalloc(NULL, Strlen("http/1.1"));
  Memcpy(alpn[1], "http/1.1", Strlen("http/1.1"));
  alpnLen[1] = Strlen("http/1.1");

  matrixSslCreateALPNext(NULL, 2, alpn, alpnLen, &ext, &extLen);
  matrixSslLoadHelloExtension(extension, ext, extLen, EXT_ALPN);
  psFree(alpn[0], NULL);
  psFree(alpn[1], NULL);
#endif

  Dout(dc::tls|continued_cf, "matrixSslNewClientSession(&m_session, s_keys, session_id(), ciphersuites, " <<
      ciphersuites_len << ", certCb, \"" << ServerNameIndication << "\", NULL, NULL, session_opts()) = ");
  ret = matrixSslNewClientSession(
      reinterpret_cast<ssl_t**>(&m_session),
      s_keys,
      session_id(),
      ciphersuites,
      ciphersuites_len,
      certCb,
      ServerNameIndication.c_str(),
      extension,
      extensionCb,
      session_opts());
  Dout(dc::finish, ret);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslNewClientSession");
  // Pass a non-empty ServerNameIndication to connect() or init(fd, ...) or call Socket::set_sni() when you only have a pointer to the Socket base class.
  ASSERT(!ServerNameIndication.empty());
  // As per documentation of matrixSslNewClientSession:
  // Success. The ssl_t context is initialized and the CLIENT_HELLO message has been encoded and is ready to be sent to the server to being the SSL handshake.
  ASSERT(ret == MATRIXSSL_REQUEST_SEND);

  Dout(dc::tls|continued_cf, "matrixSslDeleteHelloExtension(extension) = ");
  matrixSslDeleteHelloExtension(extension);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslDeleteHelloExtension");
}

int32_t TLS::matrixSslGetOutdata(char** buf_ptr)
{
  Dout(dc::tls|continued_cf, "matrixSslGetOutdata({" << *session() << "}, {");
  matrixssl_error_code ret = ::matrixSslGetOutdata(session(), reinterpret_cast<unsigned char**>(buf_ptr));
  if (AI_UNLIKELY(ret < 0))
  {
    Dout(dc::finish, "-}) = " << ret);
    THROW_FALERTC(ret, "matrixSslGetOutdata");
  }
  Dout(dc::finish, "...}) = " << ret);
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
  Dout(dc::tls|continued_cf, "matrixSslGetReadbuf({");
  matrixssl_error_code ret = ::matrixSslGetReadbuf(session(), reinterpret_cast<unsigned char**>(buf_ptr));
  if (AI_UNLIKELY(ret < 0))
  {
    Dout(dc::finish, "...}) = " << ret);
    THROW_FALERTC(ret, "matrixSslGetReadbuf");
  }
  Dout(dc::finish, (void*)*buf_ptr << "}) = " << ret);
  return ret;
}

TLS::data_result_type TLS::matrixSslReceivedData(ssize_t rlen, char const** buf_ptr, uint32_t* buf_len_ptr)
{
  Dout(dc::tls|continued_cf, "matrixSslReceivedData({" << *session() << "}, " << rlen << ", {");
  matrixssl_error_code ret = ::matrixSslReceivedData(session(), rlen, const_cast<unsigned char**>(reinterpret_cast<unsigned char const**>(buf_ptr)), buf_len_ptr);

  if (AI_UNLIKELY(ret < 0))
  {
    Dout(dc::finish, "...}, {...}) = " << ret);
    THROW_FALERTC(ret, "matrixSslReceivedData");
  }

  Dout(dc::continued, buf2str(*buf_ptr, *buf_len_ptr) << "}, {" << *buf_len_ptr << "}) = ");

  switch (ret)
  {
    case PS_SUCCESS:
      Dout(dc::finish, ret);
      return SUCCESS;

    case MATRIXSSL_REQUEST_SEND:
      Dout(dc::finish, "MATRIXSSL_REQUEST_SEND");
      return REQUEST_SEND;

    case MATRIXSSL_REQUEST_RECV:
      Dout(dc::finish, "MATRIXSSL_REQUEST_RECV");
      return REQUEST_RECV;

    case MATRIXSSL_HANDSHAKE_COMPLETE:
      Dout(dc::finish, "MATRIXSSL_HANDSHAKE_COMPLETE");
      return HANDSHAKE_COMPLETE;

    case MATRIXSSL_RECEIVED_ALERT:
      Dout(dc::finish, "MATRIXSSL_RECEIVED_ALERT");
      ASSERT(*buf_len_ptr == 2);
      return ((*buf_ptr)[0] == SSL_ALERT_LEVEL_WARNING) ? RECEIVED_ALERT_WARNING : RECEIVED_ALERT_FATAL;

    case MATRIXSSL_APP_DATA:
      Dout(dc::finish, "MATRIXSSL_APP_DATA");
      return APP_DATA;
  }
  ASSERT(ret == MATRIXSSL_APP_DATA_COMPRESSED);
  Dout(dc::finish, "MATRIXSSL_APP_DATA_COMPRESSED");
  return APP_DATA_COMPRESSED;
}

TLS::data_result_type TLS::matrixSslProcessedData(char const** buf_ptr, uint32_t* buf_len_ptr)
{
  Dout(dc::tls|continued_cf, "matrixSslProcessedData({");
  matrixssl_error_code ret = ::matrixSslProcessedData(session(), const_cast<unsigned char**>(reinterpret_cast<unsigned char const**>(buf_ptr)), buf_len_ptr);

  if (ret < 0)
  {
    Dout(dc::finish, "...}, {...}) = " << ret);
    THROW_FALERTC(ret, "matrixSslProcessedData");
  }

  Dout(dc::finish, buf2str(*buf_ptr, *buf_len_ptr) << "}, {" << *buf_len_ptr << "}) = " << ret);

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

int32_t TLS::matrixSslEncodeToOutdata(char* buf, uint32_t len)
{
  matrixssl_error_code ret = ::matrixSslEncodeToOutdata(session(), reinterpret_cast<unsigned char*>(buf), len);
  Dout(dc::tls, "TLS::matrixSslEncodeToOutdata(\"" << buf2str(buf, len) << "\", " << len << ") = " << ret);

  if (AI_UNLIKELY(ret < 0))
    THROW_FALERTC(ret, "matrixSslEncodeToOutdata");

  if (AI_LIKELY(ret > 0))
    return ret;

  // Just translate the matrixssl error to some similar system error.
  switch (ret)
  {
    case PS_LIMIT_FAIL:           // The plaintext length must be smaller than the SSL specified value of 16KB.
      return -EMSGSIZE;
    case PS_MEM_FAIL:             // The internal allocation of the destination buffer failed.
      return -ENOMEM;
    case PS_ARG_FAIL:             // Bad input parameters.
      return -EINVAL;
    case PS_PROTOCOL_FAIL:        // This session is flagged for closure.
      return -EPROTO;
  }
  ASSERT(ret == PS_FAILURE);    // Internal error managing buffers.
  return -ENOBUFS;
}

uint32_t TLS::get_max_frag() const
{
  int32 max_frag = session()->maxPtFrag;
  ASSERT(0 < max_frag && max_frag <= 0x4000);
  return max_frag;
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
