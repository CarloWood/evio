/**
 * evio -- A cwm4 git submodule for adding support for buffered, iostream oriented, epoll based I/O.
 *
 * @file
 * @brief TLS (related) definition.
 *
 * @Copyright (C) 2019  Carlo Wood.
 *
 * RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
 * Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
 *
 * This file is part of evio.
 *
 * Evio is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Evio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with evio.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sys.h"
#include "TLS.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#ifdef CWDEBUG
//#include "testkeys/RSA/2048_RSA.h"
//#include "testkeys/RSA/2048_RSA_KEY.h"
//#include "testkeys/RSA/ALL_RSA_CAS.h"
//#include "testkeys/PSK/tls13_psk.h"
#include "utils/debug_ostream_operators.h"
#include <libcwd/buf2str.h>
#include <filesystem>
#endif

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
channel_ct tls("TLS");
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {
namespace protocol {

struct wolfssl_error_code
{
  int mCode;

  wolfssl_error_code(int code) : mCode(code) { }
  operator int() const { return mCode; }
};

std::error_code make_error_code(wolfssl_error_code);

std::ostream& operator<<(std::ostream& os, wolfssl_error_code code)
{
  // Also support printing positive values as just integers...
  int val = code;
#if 0
  if (val > 0)
    os << val;
  else
#endif
    os << make_error_code(code).category().message(code);
  return os;
}

} // namespace protocol
} // namespace evio

// Register evio::wolfssl_error_code as valid error code.
namespace std {

template<> struct is_error_code_enum<evio::protocol::wolfssl_error_code> : true_type { };

} // namespace std

namespace evio {
namespace protocol {

std::once_flag TLS::s_flag;

namespace {

WOLFSSL_CTX* s_ctx;

#if 0
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
#endif

} // namespace

#if 0   // IOReadCtx / IOWriteCtx not set.
#ifdef CWDEBUG
std::ostream& operator<<(std::ostream& os, WOLFSSL const& session)
{
  FileDescriptor const* input_device = static_cast<InputDevice*>(wolfSSL_GetIOReadCtx(const_cast<WOLFSSL*>(&session)));
  FileDescriptor const* output_device = static_cast<OutputDevice*>(wolfSSL_GetIOWriteCtx(const_cast<WOLFSSL*>(&session)));
  if (input_device == output_device)
    os << input_device;
  else
    os << "{input:" << input_device << ",output:" << output_device << '}';
  return os;
}
#endif
#endif

//inline
auto TLS::session() const
{
  return static_cast<WOLFSSL*>(m_session);
}

#if 0
//inline
auto TLS::session_opts() const
{
  return static_cast<sslSessOpts_t*>(m_session_opts);
}

//inline
auto TLS::session_id() const
{
  return static_cast<sslSessionId_t*>(m_session_id);
}
#endif

std::vector<std::string> TLS::get_CA_files()
{
  std::vector<std::string> CA_files;

  // TODO: Add other standard file paths and directories and support for environment variables
  // like REQUESTS_CA_BUNDLE, SSL_CERT_FILE and SSL_CERT_DIR.
  // See also https://serverfault.com/a/722646.

  // Arch linux:
  CA_files.push_back("/etc/ssl/cert.pem");
  // Debian/Ubuntu/Gentoo etc (debian based distributions):
  //return "/etc/ssl/certs/ca-certificates.crt";
  // RHEL 6:
  // "/etc/pki/tls/certs/ca-bundle.crt"
  // RHEL 7 / CentOS:
  // "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
  // See also https://techjourney.net/update-add-ca-certificates-bundle-in-redhat-centos/

#ifdef CWDEBUG
  std::filesystem::path const wolfssl_CA_cert_file = "/usr/src/AUR/wolfssl/wolfssl-examples-git/certs/ca-cert.pem";
  if (std::filesystem::exists(wolfssl_CA_cert_file))
    CA_files.push_back(wolfssl_CA_cert_file);
#endif

  return CA_files;
}

class TLS::WolfSSL_Cleanup
{
 private:
  bool m_need_deinitialization;

 public:
  WolfSSL_Cleanup() : m_need_deinitialization(false) { }
  ~WolfSSL_Cleanup() { if (m_need_deinitialization) TLS::global_tls_deinitialization(); }
  void initialized() { m_need_deinitialization = true; }
};

namespace {

class WolfSSL_CTX
{
 private:
  WOLFSSL_CTX* m_context;

 public:
  WolfSSL_CTX() : m_context(nullptr) { }
  ~WolfSSL_CTX() { destroy(); }
  void create()
  {
    // Create and initialize a WOLFSSL_CTX that will try to negotiate the highest possible version of TLS that is supported...
    Dout(dc::tls|continued_cf, "wolfSSL_CTX_new(wolfTLS_client_method()) = ");
    m_context = wolfSSL_CTX_new(wolfTLS_client_method());
    Dout(dc::finish, m_context);
    if (!m_context)
    {
      // This can be out of memory or a failure of InitSSL_Ctx() (BAD_MUTEX_E) or failure of wolfSSL_CertManagerNew_ex() (BAD_CERT_MANAGER_ERROR).
      // However, the latter only fails when wc_InitMutex return 0, which exactly what BAD_MUTEX_E is.
      // Moreover, InitSSL_Ctx() only fails when osMutexNew() return NULL. It seems very likely that this will never happen on linux,
      // or - if it happens - is also caused by an out of memory (although I wasn't able to verify this).
      THROW_FALERTC(ENOMEM, "wolfSSL_CTX_new returned NULL");
    }
#if defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_TLS13)
    // Seems wolfSSL was configured wrong.
    #error "wolfSSL supports neither TLS v1.2 nor v1.3"
#else
    // ... but no less than TLS v1.2.
    Dout(dc::tls|continued_cf, "wolfSSL_CTX_SetMinVersion(" << m_context << ", WOLFSSL_TLSV1_2) = ");
    wolfssl_error_code ret = wolfSSL_CTX_SetMinVersion(m_context, WOLFSSL_TLSV1_2);
    Dout(dc::finish, ret);
    if (ret != WOLFSSL_SUCCESS)
      THROW_ALERT("libwolfssl does not support TLS v1.2");
#endif
  }
  void destroy() noexcept
  {
    if (m_context)
    {
      Dout(dc::tls, "wolfSSL_CTX_free(" << m_context << ")");
      wolfSSL_CTX_free(m_context);
    }
    m_context = nullptr;
  }

  operator WOLFSSL_CTX*() const
  {
    return m_context;
  }
};

// Global SSL context.
WolfSSL_CTX s_context;

// Cause TLS::global_tls_deinitialization() to be called when destructing global objects.
TLS::WolfSSL_Cleanup s_cleanup_hook;

} // namespace

//static
void TLS::global_tls_initialization()
{
  DoutEntering(dc::tls|dc::notice, "evio::protocol::TLS::global_tls_initialization()");

  // Call this to have wolfssl print debug output (wolfssl must be configured with --enable-debug).
  //wolfSSL_Debugging_ON();

  Dout(dc::tls|continued_cf, "wolfSSL_Init() = ");
  wolfssl_error_code ret = wolfSSL_Init();
  Dout(dc::finish, ret);
  if (ret != WOLFSSL_SUCCESS)
    THROW_FALERTC(ret, "wolfSSL_Init");

  // Create WOLFSSL_CTX.
  s_context.create();

  // Load client certificates into WOLFSSL_CTX.
  for (auto&& CA_file : get_CA_files())
  {
    Dout(dc::tls|continued_cf, "wolfSSL_CTX_load_verify_locations(s_context, \"" << CA_file << "\", NULL) = ");
    ret = wolfSSL_CTX_load_verify_locations(s_context, CA_file.c_str(), NULL);
    Dout(dc::finish, ret);
    if (ret != SSL_SUCCESS) {
      s_context.destroy();
      THROW_FALERTC(ret, "Failed to load Certificate Authority file \"[CA_FILE]\".", AIArgs("[CA_FILE]", CA_file));
    }
  }

  // Initialization will succeed (no more throws follow).
  s_cleanup_hook.initialized();

#if 0
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
#endif

#ifdef CWDEBUG
#if 0
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
#endif
#endif // CWDEBUG
}

//static
void TLS::global_tls_deinitialization() noexcept
{
  DoutEntering(dc::tls|dc::notice, "evio::protocol::TLS::global_tls_deinitialization()");

  // Destroy global SSL context.
  s_context.destroy();

  Dout(dc::tls, "wolfSSL_Cleanup()");
  wolfSSL_Cleanup();
}

TLS::TLS() : m_session(nullptr) /*, m_session_opts(nullptr), m_session_id(nullptr)*/
{
  DoutEntering(dc::tls, "TLS::TLS() [" << this << "]");
  std::call_once(s_flag, global_tls_initialization);
}

TLS::~TLS()
{
  DoutEntering(dc::tls, "TLS::~TLS()");
  Dout(dc::tls, "wolfSSL_free(" << session() << ")");
  // Not documented, but you can call wolfSSL_free with a nullptr, which is a no-op.
  wolfSSL_free(session());
}

// Get SSL error string.
//static
std::string TLS::session_error_string(int session_error)
{
  std::string errorString(WOLFSSL_MAX_ERROR_SZ, '\0');  // Reserve space.
  wolfSSL_ERR_error_string(session_error, errorString.data());
  errorString.resize(errorString.find('\0'));           // Truncate to C string length.
  return errorString;
}

#if 0
// Certificate callback. See section 6 in the API manual for details.
static int32_t certCb(ssl_t* UNUSED_ARG(ssl), psX509Cert_t* UNUSED_ARG(cert), int32_t alert)
{
  // No extra checks of our own; simply accept the result of MatrixSSL's internal certificate validation.
  return alert;
}
#endif

#if 0
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
#endif

void TLS::session_init(std::string const& ServerNameIndication)    // SNI
{
  DoutEntering(dc::tls, "TLS::session_init(\"" << ServerNameIndication << "\")");
  // Only call session_init() once.
  ASSERT(!m_session);
  Dout(dc::tls|continued_cf, "wolfSSL_new(" << s_context << ") = ");
  m_session = wolfSSL_new(s_context);
  Dout(dc::finish, m_session);
  if (!m_session)
    THROW_FALERT("wolfSSL_new returned NULL");
#if 0
  Dout(dc::tls|continued_cf, "wolfSSL_UseSNI(" << session() << ", WOLFSSL_SNI_HOST_NAME, \"" << ServerNameIndication << "\", " << ServerNameIndication.length() << ") = ");
  wolfssl_error_code ret = wolfSSL_UseSNI(session(), WOLFSSL_SNI_HOST_NAME, ServerNameIndication.c_str(), ServerNameIndication.length());
  Dout(dc::finish, ret);
  if (ret != WOLFSSL_SUCCESS)
    THROW_FALERTC(ret, "wolfSSL_UseSNI([SSL], WOLFSSL_SNI_HOST_NAME, [SNI], [SNILEN])",
        AIArgs("[SSL]", session())("SNI", ServerNameIndication)("SNILEN", ServerNameIndication.length()));
#endif

#if 0
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
#endif
}

void TLS::set_fd(int fd)
{
  Dout(dc::tls|continued_cf, "wolfSSL_set_fd(" << session() << ", " << fd << ") = ");
  wolfssl_error_code ret = wolfSSL_set_fd(session(), fd);
  Dout(dc::finish, ret);
  if (AI_UNLIKELY(ret != WOLFSSL_SUCCESS))
    THROW_FALERTC(ret, "wolfSSL_set_fd");
}

TLS::result_type TLS::do_handshake()
{
  Dout(dc::tls|continued_cf, "wolfSSL_connect(" << session() << ") = ");
  wolfssl_error_code ssl_result = wolfSSL_connect(session());
#ifdef CWDEBUG
  if (ssl_result == WOLFSSL_FATAL_ERROR)
  {
    wolfssl_error_code session_error = wolfSSL_get_error(session(), 0);
    Dout(dc::finish, (int)ssl_result << " (" << session_error << ": " << session_error_string(session_error) << ")");
  }
  else
    Dout(dc::finish, ssl_result);
#endif
  if (ssl_result == SSL_SUCCESS)
    return HANDSHAKE_COMPLETE;
  else if (wolfSSL_want_write(session()))
  {
    Dout(dc::tls, "wolfSSL_want_write(" << session() << ") returned true.");
    return HANDSHAKE_WANT_WRITE;
  }
  else if (wolfSSL_want_read(session()))
  {
    Dout(dc::tls, "wolfSSL_want_read(" << session() << ") returned true.");
    return HANDSHAKE_WANT_READ;
  }
  else
  {
    assert(false); // To be implemented.
  }
}

#if 0
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
#endif

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
      return "wolfTLS ErrorCategory::message (unrecognized error)";
  }
}

ErrorCategory const theErrorCategory { };

} // namespace

std::error_code make_error_code(error_codes code)
{
  return std::error_code(static_cast<int>(code), theErrorCategory);
}

//----------------------------------------------------------------------------
// wolfssl error codes (as returned by wolfssl_connect, etc)

namespace {

struct WolfSSLErrorCategory : std::error_category
{
  char const* name() const noexcept override;
  std::string message(int ev) const override;
};

char const* WolfSSLErrorCategory::name() const noexcept
{
  return "wolfssl";
}

std::string WolfSSLErrorCategory::message(int ev) const
{
  switch (ev)
  {
    AI_CASE_RETURN(SSL_SUCCESS);
    // wolfSSL_Init errors.
    //AI_CASE_RETURN(BAD_MUTEX_E);
    //AI_CASE_RETURN(WC_INIT_E);          // wolfCrypt initialization error.
    // wolfSSL_CTX_load_verify_locations errors.
    AI_CASE_RETURN(SSL_FAILURE);        // Will be returned if ctx is NULL, or if both file and path are NULL.
    AI_CASE_RETURN(SSL_BAD_FILETYPE);   // Will be returned if the file is the wrong format.
    AI_CASE_RETURN(SSL_BAD_FILE);       // Will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    //AI_CASE_RETURN(MEMORY_E);           // Will be returned if an out of memory condition occurs.
    //AI_CASE_RETURN(ASN_INPUT_E);        // Will be returned if Base16 decoding fails on the file.
    //AI_CASE_RETURN(ASN_BEFORE_DATE_E);  // Will be returned if the current date is before the before date.
    //AI_CASE_RETURN(ASN_AFTER_DATE_E);   // Will be returned if the current date is after the after date.
    //AI_CASE_RETURN(BUFFER_E);           // Will be returned if a chain buffer is bigger than the receiving buffer.
    //AI_CASE_RETURN(BAD_PATH_ERROR);     // Will be returned if opendir() fails when trying to open path.
    // wolfSSL_connect errors.
    AI_CASE_RETURN(SSL_FATAL_ERROR);    // Will be returned if an error occurred. To get a more detailed error code, call wolfSSL_get_error().
    // wolfSSL_get_error.
    AI_CASE_RETURN(UNSUPPORTED_SUITE);
    AI_CASE_RETURN(INPUT_CASE_ERROR);
    AI_CASE_RETURN(PREFIX_ERROR);
    AI_CASE_RETURN(MEMORY_ERROR);
    AI_CASE_RETURN(VERIFY_FINISHED_ERROR);
    AI_CASE_RETURN(VERIFY_MAC_ERROR);
    AI_CASE_RETURN(PARSE_ERROR);
    AI_CASE_RETURN(SIDE_ERROR);
    AI_CASE_RETURN(NO_PEER_CERT);
    AI_CASE_RETURN(UNKNOWN_HANDSHAKE_TYPE);
    AI_CASE_RETURN(SOCKET_ERROR_E);
    AI_CASE_RETURN(SOCKET_NODATA);
    AI_CASE_RETURN(INCOMPLETE_DATA);
    AI_CASE_RETURN(UNKNOWN_RECORD_TYPE);
    AI_CASE_RETURN(DECRYPT_ERROR);
    AI_CASE_RETURN(FATAL_ERROR);
    AI_CASE_RETURN(ENCRYPT_ERROR);
    AI_CASE_RETURN(FREAD_ERROR);
    AI_CASE_RETURN(NO_PEER_KEY);
    AI_CASE_RETURN(NO_PRIVATE_KEY);
    AI_CASE_RETURN(NO_DH_PARAMS);
    AI_CASE_RETURN(RSA_PRIVATE_ERROR);
    AI_CASE_RETURN(MATCH_SUITE_ERROR);
    AI_CASE_RETURN(COMPRESSION_ERROR);
    AI_CASE_RETURN(BUILD_MSG_ERROR);
    AI_CASE_RETURN(BAD_HELLO);
    AI_CASE_RETURN(DOMAIN_NAME_MISMATCH);
    AI_CASE_RETURN(IPADDR_MISMATCH);
    AI_CASE_RETURN(WANT_READ);
    AI_CASE_RETURN(WOLFSSL_ERROR_WANT_READ);
    AI_CASE_RETURN(NOT_READY_ERROR);
    AI_CASE_RETURN(VERSION_ERROR);
    AI_CASE_RETURN(WANT_WRITE);
    AI_CASE_RETURN(WOLFSSL_ERROR_WANT_WRITE);
    AI_CASE_RETURN(BUFFER_ERROR);
    // crypto API errors.
    AI_CASE_RETURN(OPEN_RAN_E);
    AI_CASE_RETURN(READ_RAN_E);
    AI_CASE_RETURN(WINCRYPT_E);
    AI_CASE_RETURN(CRYPTGEN_E);
    AI_CASE_RETURN(RAN_BLOCK_E);
    AI_CASE_RETURN(BAD_MUTEX_E);
    AI_CASE_RETURN(WC_TIMEOUT_E);
    AI_CASE_RETURN(WC_PENDING_E);
    AI_CASE_RETURN(WC_NOT_PENDING_E);
    AI_CASE_RETURN(MP_INIT_E);
    AI_CASE_RETURN(MP_READ_E);
    AI_CASE_RETURN(MP_EXPTMOD_E);
    AI_CASE_RETURN(MP_TO_E);
    AI_CASE_RETURN(MP_SUB_E);
    AI_CASE_RETURN(MP_ADD_E);
    AI_CASE_RETURN(MP_MUL_E);
    AI_CASE_RETURN(MP_MULMOD_E);
    AI_CASE_RETURN(MP_MOD_E);
    AI_CASE_RETURN(MP_INVMOD_E);
    AI_CASE_RETURN(MP_CMP_E);
    AI_CASE_RETURN(MP_ZERO_E);
    AI_CASE_RETURN(MEMORY_E);
    AI_CASE_RETURN(VAR_STATE_CHANGE_E);
    AI_CASE_RETURN(RSA_WRONG_TYPE_E);
    AI_CASE_RETURN(RSA_BUFFER_E);
    AI_CASE_RETURN(BUFFER_E);
    AI_CASE_RETURN(ALGO_ID_E);
    AI_CASE_RETURN(PUBLIC_KEY_E);
    AI_CASE_RETURN(DATE_E);
    AI_CASE_RETURN(SUBJECT_E);
    AI_CASE_RETURN(ISSUER_E);
    AI_CASE_RETURN(CA_TRUE_E);
    AI_CASE_RETURN(EXTENSIONS_E);
    AI_CASE_RETURN(ASN_PARSE_E);
    AI_CASE_RETURN(ASN_VERSION_E);
    AI_CASE_RETURN(ASN_GETINT_E);
    AI_CASE_RETURN(ASN_RSA_KEY_E);
    AI_CASE_RETURN(ASN_OBJECT_ID_E);
    AI_CASE_RETURN(ASN_TAG_NULL_E);
    AI_CASE_RETURN(ASN_EXPECT_0_E);
    AI_CASE_RETURN(ASN_BITSTR_E);
    AI_CASE_RETURN(ASN_UNKNOWN_OID_E);
    AI_CASE_RETURN(ASN_DATE_SZ_E);
    AI_CASE_RETURN(ASN_BEFORE_DATE_E);
    AI_CASE_RETURN(ASN_AFTER_DATE_E);
    AI_CASE_RETURN(ASN_SIG_OID_E);
    AI_CASE_RETURN(ASN_TIME_E);
    AI_CASE_RETURN(ASN_INPUT_E);
    AI_CASE_RETURN(ASN_SIG_CONFIRM_E);
    AI_CASE_RETURN(ASN_SIG_HASH_E);
    AI_CASE_RETURN(ASN_SIG_KEY_E);
    AI_CASE_RETURN(ASN_DH_KEY_E);
    AI_CASE_RETURN(ASN_NTRU_KEY_E);
    AI_CASE_RETURN(ASN_CRIT_EXT_E);
    AI_CASE_RETURN(ASN_ALT_NAME_E);
    AI_CASE_RETURN(ECC_BAD_ARG_E);
    AI_CASE_RETURN(ASN_ECC_KEY_E);
    AI_CASE_RETURN(ECC_CURVE_OID_E);
    AI_CASE_RETURN(BAD_FUNC_ARG);
    AI_CASE_RETURN(NOT_COMPILED_IN);
    AI_CASE_RETURN(UNICODE_SIZE_E);
    AI_CASE_RETURN(NO_PASSWORD);
    AI_CASE_RETURN(ALT_NAME_E);
    AI_CASE_RETURN(AES_GCM_AUTH_E);
    AI_CASE_RETURN(AES_CCM_AUTH_E);
    AI_CASE_RETURN(ASYNC_INIT_E);
    AI_CASE_RETURN(COMPRESS_INIT_E);
    AI_CASE_RETURN(COMPRESS_E);
    AI_CASE_RETURN(DECOMPRESS_INIT_E);
    AI_CASE_RETURN(DECOMPRESS_E);
    AI_CASE_RETURN(BAD_ALIGN_E);
    AI_CASE_RETURN(ASN_NO_SIGNER_E);
    AI_CASE_RETURN(ASN_CRL_CONFIRM_E);
    AI_CASE_RETURN(ASN_CRL_NO_SIGNER_E);
    AI_CASE_RETURN(ASN_OCSP_CONFIRM_E);
    AI_CASE_RETURN(ASN_NO_PEM_HEADER);
    AI_CASE_RETURN(BAD_STATE_E);
    AI_CASE_RETURN(BAD_PADDING_E);
    AI_CASE_RETURN(REQ_ATTRIBUTE_E);
    AI_CASE_RETURN(PKCS7_OID_E);
    AI_CASE_RETURN(PKCS7_RECIP_E);
    AI_CASE_RETURN(WC_PKCS7_WANT_READ_E);
    AI_CASE_RETURN(FIPS_NOT_ALLOWED_E);
    AI_CASE_RETURN(ASN_NAME_INVALID_E);
    AI_CASE_RETURN(RNG_FAILURE_E);
    AI_CASE_RETURN(HMAC_MIN_KEYLEN_E);
    AI_CASE_RETURN(RSA_PAD_E);
    AI_CASE_RETURN(LENGTH_ONLY_E);
    AI_CASE_RETURN(IN_CORE_FIPS_E);
    AI_CASE_RETURN(AES_KAT_FIPS_E);
    AI_CASE_RETURN(DES3_KAT_FIPS_E);
    AI_CASE_RETURN(HMAC_KAT_FIPS_E);
    AI_CASE_RETURN(RSA_KAT_FIPS_E);
    AI_CASE_RETURN(DRBG_KAT_FIPS_E);
    AI_CASE_RETURN(DRBG_CONT_FIPS_E);
    AI_CASE_RETURN(AESGCM_KAT_FIPS_E);
    AI_CASE_RETURN(THREAD_STORE_KEY_E);
    AI_CASE_RETURN(THREAD_STORE_SET_E);
    AI_CASE_RETURN(MAC_CMP_FAILED_E);
    AI_CASE_RETURN(IS_POINT_E);
    AI_CASE_RETURN(ECC_INF_E);
    AI_CASE_RETURN(ECC_OUT_OF_RANGE_E);
    AI_CASE_RETURN(ECC_PRIV_KEY_E);
    AI_CASE_RETURN(SRP_CALL_ORDER_E);
    AI_CASE_RETURN(SRP_VERIFY_E);
    AI_CASE_RETURN(SRP_BAD_KEY_E);
    AI_CASE_RETURN(ASN_NO_SKID);
    AI_CASE_RETURN(ASN_NO_AKID);
    AI_CASE_RETURN(ASN_NO_KEYUSAGE);
    AI_CASE_RETURN(SKID_E);
    AI_CASE_RETURN(AKID_E);
    AI_CASE_RETURN(KEYUSAGE_E);
    AI_CASE_RETURN(EXTKEYUSAGE_E);
    AI_CASE_RETURN(CERTPOLICIES_E);
    AI_CASE_RETURN(WC_INIT_E);
    AI_CASE_RETURN(SIG_VERIFY_E);
    AI_CASE_RETURN(BAD_COND_E);
    AI_CASE_RETURN(SIG_TYPE_E);
    AI_CASE_RETURN(HASH_TYPE_E);
    AI_CASE_RETURN(WC_KEY_SIZE_E);
    AI_CASE_RETURN(ASN_COUNTRY_SIZE_E);
    AI_CASE_RETURN(MISSING_RNG_E);
    AI_CASE_RETURN(ASN_PATHLEN_SIZE_E);
    AI_CASE_RETURN(ASN_PATHLEN_INV_E);
    AI_CASE_RETURN(BAD_KEYWRAP_ALG_E);
    AI_CASE_RETURN(BAD_KEYWRAP_IV_E);
    AI_CASE_RETURN(WC_CLEANUP_E);
    AI_CASE_RETURN(ECC_CDH_KAT_FIPS_E);
    AI_CASE_RETURN(DH_CHECK_PUB_E);
    AI_CASE_RETURN(BAD_PATH_ERROR);
    AI_CASE_RETURN(ASYNC_OP_E);
    AI_CASE_RETURN(BAD_OCSP_RESPONDER);
    AI_CASE_RETURN(ECC_PRIVATEONLY_E);
    AI_CASE_RETURN(WC_HW_E);
    AI_CASE_RETURN(WC_HW_WAIT_E);
    AI_CASE_RETURN(PSS_SALTLEN_E);
    AI_CASE_RETURN(PRIME_GEN_E);
    AI_CASE_RETURN(BER_INDEF_E);
    AI_CASE_RETURN(RSA_OUT_OF_RANGE_E);
    AI_CASE_RETURN(RSAPSS_PAT_FIPS_E);
    AI_CASE_RETURN(ECDSA_PAT_FIPS_E);
    AI_CASE_RETURN(DH_KAT_FIPS_E);
    AI_CASE_RETURN(AESCCM_KAT_FIPS_E);
    AI_CASE_RETURN(SHA3_KAT_FIPS_E);
    AI_CASE_RETURN(ECDHE_KAT_FIPS_E);
    AI_CASE_RETURN(AES_GCM_OVERFLOW_E);
    AI_CASE_RETURN(AES_CCM_OVERFLOW_E);
    AI_CASE_RETURN(RSA_KEY_PAIR_E);
    AI_CASE_RETURN(DH_CHECK_PRIV_E);
    AI_CASE_RETURN(WC_AFALG_SOCK_E);
    AI_CASE_RETURN(WC_DEVCRYPTO_E);
    AI_CASE_RETURN(ZLIB_INIT_ERROR);
    AI_CASE_RETURN(ZLIB_COMPRESS_ERROR);
    AI_CASE_RETURN(ZLIB_DECOMPRESS_ERROR);
    AI_CASE_RETURN(PKCS7_NO_SIGNER_E);
    AI_CASE_RETURN(CRYPTOCB_UNAVAILABLE);
    AI_CASE_RETURN(PKCS7_SIGNEEDS_CHECK);
    AI_CASE_RETURN(PSS_SALTLEN_RECOVER_E);
    AI_CASE_RETURN(ASN_SELF_SIGNED_E);
  }
  return "Unknown error " + std::to_string(ev);
}

WolfSSLErrorCategory const theWolfSSLErrorCategory { };

} // namespace

std::error_code make_error_code(wolfssl_error_code code)
{
  return std::error_code(static_cast<int>(code), theWolfSSLErrorCategory);
}

} // namespace protocol
} // namespace evio
