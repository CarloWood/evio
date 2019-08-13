#include "sys.h"
#include "TLS.h"
#include "matrixssl/matrixsslApi.h"
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

void TLS::global_tls_initialization()
{
  DoutEntering(dc::notice, "evio::protocol::TLS::global_tls_initialization()");

  matrixssl_error_code ret = matrixSslOpen();
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
  DoutEntering(dc::notice, "evio::protocol::TLS::global_tls_deinitialization()");

  if (s_keys)
  {
    matrixSslDeleteKeys(s_keys);
    s_keys = nullptr;
  }

  matrixSslClose();
}

TLS::TLS() : m_session(nullptr), m_session_opts(nullptr)
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

void TLS::session_init(char const* http_server_name, size_t http_server_name_length)
{
  DoutEntering(dc::tls, "TLS::session_init(\"" << http_server_name << "\", " << http_server_name_length << ")");
  // Only call session_init() once.
  ASSERT(!m_session_opts);
  m_session_opts = calloc(sizeof(sslSessOpts_t), 1);

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

  // Set supported signature algorithms.
  ret = matrixSslSessOptsSetSigAlgs(session_opts(), sigalgs, sigalgs_len);
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslSessOptsSetSigAlgs");

  ret = matrixSslNewClientSession(
      reinterpret_cast<ssl_t**>(&m_session),
      s_keys,
      NULL,
      ciphersuites,
      ciphersuites_len,
      certCb,
      NULL,
      NULL,
      NULL,
      session_opts());
  if (ret < 0)
    THROW_FALERTC(ret, "matrixSslNewClientSession");

#if 0
  // Initialize TLS session.
  gnutls_error_codes err = gnutls_init(&m_session, GNUTLS_CLIENT|GNUTLS_NONBLOCK);
  if (err < 0)
    THROW_FALERTC(err, "gnutls_init");

  // Use default priorities.
  err = gnutls_set_default_priority(m_session);
  if (err < 0)
    THROW_FALERTC(err, "gnutls_set_default_priority");

  // Put the x509 credentials to the current session.
  err = gnutls_credentials_set(m_session, GNUTLS_CRD_CERTIFICATE, s_xcred);
  if (err < 0)
    THROW_FALERTC(err, "gnutls_credentials_set");

  if (http_server_name)
  {
    err = gnutls_server_name_set(m_session, GNUTLS_NAME_DNS, http_server_name, http_server_name_length);
    if (err < 0)
      THROW_FALERTC(err, "gnutls_server_name_set");
    Dout(dc::gnutls, "Server name set to \"" << http_server_name << "\" [" << this << "]");

    gnutls_session_set_verify_cert(m_session, http_server_name, 0);
  }

  gnutls_transport_set_ptr2(m_session, m_input_device.get(), m_output_device.get());
  gnutls_transport_set_push_function(m_session, system_write);
  gnutls_transport_set_pull_function(m_session, system_read);
  gnutls_transport_set_pull_timeout_function(m_session, system_recv_timeout);

  gnutls_session_set_data(m_session, m_rdata.data, m_rdata.size);

  do
  {
    gnutls_handshake_set_timeout(m_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    try
    {
      err = gnutls_handshake(m_session);
      if (err < 0)
        THROW_FALERTC(err, "gnutls_handshake");
    }
    catch (AIAlert::Error const& error)
    {
      Dout(dc::warning, error);
    }
  }
  while (err < 0 && gnutls_error_is_fatal(err) == 0);
#endif
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
    AI_CASE_RETURN(PS_SUCCESS);
    AI_CASE_RETURN(PS_FAILURE);
    AI_CASE_RETURN(PS_MEM_FAIL);
    AI_CASE_RETURN(PS_CERT_AUTH_FAIL);
    AI_CASE_RETURN(PS_PLATFORM_FAIL);
    AI_CASE_RETURN(PS_ARG_FAIL);
    AI_CASE_RETURN(PS_PARSE_FAIL);
    AI_CASE_RETURN(PS_UNSUPPORTED_FAIL);
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
