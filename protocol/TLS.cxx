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
#include <filesystem>
#include "utils/debug_ostream_operators.h"
#include "utils/print_using.h"
#include <libcwd/buf2str.h>
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

} // namespace

#ifdef CWDEBUG
std::ostream& operator<<(std::ostream& os, WOLFSSL const* session)
{
  return os << "(WOLFSSL*)" << (void*)session;
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

class TLS::Cleanup
{
 private:
  bool m_need_deinitialization;

 public:
  Cleanup() : m_need_deinitialization(false) { }
  ~Cleanup() { if (m_need_deinitialization) TLS::global_tls_deinitialization(); }
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

#ifdef CWDEBUG
void print_buf2hex_on(std::ostream& os, std::string_view const& sv)
{
  std::ios save_format(nullptr);
  save_format.copyfmt(os);

  constexpr int nb = 6;
  char const* buf = sv.data();
  int const len = sv.size();
  bool const small = len <= 2 * nb;
  int mn = small ? len : nb;
  os << std::hex << std::setfill('0') << std::setw(2);
  char const* separator = "0x";
  for (int n = 0; n < mn; ++n)
  {
    os << separator << (int)(unsigned char)buf[n];
    separator = " 0x";
  }
  if (!small)
  {
    os << " ...";
    for (size_t n = len - nb; n < len; ++n)
    {
      os << separator << (int)(unsigned char)buf[n];
      separator = " 0x";
    }
  }

  // Restore previous formatting settings.
  os.copyfmt(save_format);
}
#endif

// Global SSL context.
WolfSSL_CTX s_context;

// Cause TLS::global_tls_deinitialization() to be called when destructing global objects.
TLS::Cleanup s_cleanup_hook;

} // namespace

//inline
int TLS::send(char* buf, int len)
{
  DoutEntering(dc::evio, "TLS::send(" << (void*)buf << ", " << len << ") [" << static_cast<WOLFSSL*>(m_write_session) << ", " << m_output_device.get() << "]");
  int wlen;

  for (;;) // EINTR loop.
  {
    Dout(dc::system|dc::tls|continued_cf, "send(" << m_send_fd << ", \"" << utils::print_using(std::string_view(buf, len), print_buf2hex_on) << "\", " << len << ", 0) = ");
    wlen = ::send(m_send_fd, buf, len, 0);
    if (AI_UNLIKELY(wlen < 0))
    {
      Dout(dc::finish|error_cf, wlen);
      int const err = errno;
      if (err == EWOULDBLOCK || err == EAGAIN)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
      if (err == EINTR)
        continue;
      // For more detailed error reporting, store the error in the TLS struct.
      m_send_error = err;
      if (err == ECONNRESET)
        return WOLFSSL_CBIO_ERR_CONN_RST;
      if (err == EPIPE)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
      return WOLFSSL_CBIO_ERR_GENERAL;
    }
#ifdef DEBUGDEVICESTATS
    m_sent_bytes += wlen;
#endif
    Dout(dc::continued, wlen
#ifdef DEBUGDEVICESTATS
        << " [total sent now " << m_sent_bytes << " bytes]"
#endif
    );
#ifdef CWDEBUG
    if (wlen < len)      // This means we can't write more at the moment.
      Dout(dc::finish, " (Tried to write " << len << " bytes)");
    else
      Dout(dc::finish, "");
#endif
    break;
  }

  return wlen;
}

static int send(WOLFSSL*, char* buf, int len, void* tls_ptr)
{
  // Set with wolfSSL_CTX_SetIOSend below.
  TLS* tls = static_cast<TLS*>(tls_ptr);
  return tls->send(buf, len);
}

//inline
int TLS::recv(char* buf, int space)
{
  DoutEntering(dc::evio, "TLS::recv(" << (void*)buf << ", " << space << ") [" << static_cast<WOLFSSL*>(m_read_session) << ", " << m_input_device.get() << "]");

  int rlen;
  for (;;) // EINTR loop.
  {
    Dout(dc::system|dc::tls|continued_cf, "recv(" << m_recv_fd << ", ");
    rlen = ::recv(m_recv_fd, buf, space, 0);
    if (rlen > 0)
    {
#ifdef DEBUGDEVICESTATS
      m_received_bytes += rlen;
#endif
      Dout(dc::finish, "{\"" << utils::print_using(std::string_view(buf, rlen), print_buf2hex_on) << "\"}, " << space << ", 0) = " << rlen
#ifdef DEBUGDEVICESTATS
        << " [total received now: " << m_received_bytes << " bytes]"
#endif
      );
    }
    else
    {
      int const err = errno;
      Dout(dc::finish|cond_error_cf(rlen < 0), (void*)buf << ", " << space << ", 0) = " << rlen);
      if (AI_UNLIKELY(rlen <= 0))
      {
        if (err == EWOULDBLOCK || err == EAGAIN)
          return WOLFSSL_CBIO_ERR_WANT_READ;
        if (err == EINTR)
          continue;
        if (rlen == 0)
        {
          if (space == 0)
          {
            // From recv(2): the value 0 may also be returned if the requested
            // number of bytes to receive from a stream socket was 0.
            return 0;
          }
          return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        m_recv_error = err;
        if (err == ECONNRESET)
          return WOLFSSL_CBIO_ERR_CONN_RST;
        return WOLFSSL_CBIO_ERR_GENERAL;
      }
    }

    break;
  }

  return rlen;
}

static int recv(WOLFSSL*, char* buf, int space, void* tls_ptr)
{
  // Set with wolfSSL_CTX_SetIORecv below.
  TLS* tls = static_cast<TLS*>(tls_ptr);
  return tls->recv(buf, space);
}

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

  // Set I/O callbacks.
  wolfSSL_CTX_SetIORecv(s_context, protocol::recv);
  wolfSSL_CTX_SetIOSend(s_context, protocol::send);

  // Initialization will succeed (no more throws follow).
  s_cleanup_hook.initialized();
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

#ifdef DEBUGDEVICESTATS
TLS::TLS(size_t& sent_bytes, size_t& received_bytes)
#else
TLS::TLS()
#endif
  : m_read_session(nullptr), m_write_session(nullptr), m_session_state(s_want_write)
#ifdef DEBUGDEVICESTATS
  , m_sent_bytes(sent_bytes), m_received_bytes(received_bytes)
#endif
{
  DoutEntering(dc::tls, "TLS::TLS() [" << this << "]");
  std::call_once(s_flag, global_tls_initialization);
}

TLS::~TLS()
{
  DoutEntering(dc::tls, "TLS::~TLS()");
  WOLFSSL* read_session = static_cast<WOLFSSL*>(m_read_session);
  WOLFSSL* write_session = static_cast<WOLFSSL*>(m_write_session);
  Dout(dc::tls, "wolfSSL_free(" << read_session << ")");
  // Not documented, but you can call wolfSSL_free with a nullptr, which is a no-op.
  wolfSSL_free(read_session);
  if (write_session != read_session)
    wolfSSL_free(write_session);
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

//static
std::string_view TLS::session_state_to_str(int session_state)
{
  std::string str;
  if ((session_state & s_want_write))
    str += "|s_want_write";
  if ((session_state & s_inside_do_handshake))
    str += "|s_inside_do_handshake";
  if ((session_state & s_post_handshake))
    str += "|s_post_handshake";
  if ((session_state & s_have_plain_text))
    str += "|s_have_plain_text";
  if ((session_state & s_handshake_completed))
    str += "|s_handshake_completed";
  if ((session_state & s_handshake_error))
    str += "|s_handshake_error";
  std::string_view result = str;
  result.remove_prefix(1);
  return result;
}

void TLS::set_device(InputDevice* input_device, int recv_fd, OutputDevice* output_device, int send_fd)
{
  DoutEntering(dc::tls, "TLS::set_device(" << input_device << ", " << recv_fd << ", " << output_device << ", " << send_fd << ")");
  m_input_device = input_device;
  // Pass the correct recv_fd.
  ASSERT(recv_fd == m_input_device->get_fd());
  m_recv_fd = recv_fd;
  m_output_device = output_device;
  // Pass the correct send_fd.
  ASSERT(send_fd = m_output_device->get_fd());
  m_send_fd = send_fd;
}

void TLS::session_init(std::string const& ServerNameIndication)    // SNI
{
  DoutEntering(dc::tls, "TLS::session_init(\"" << ServerNameIndication << "\")");
  // Only call session_init() once.
  ASSERT(!m_read_session);
  Dout(dc::tls|continued_cf, "wolfSSL_new(" << s_context << ") = ");
  WOLFSSL* session = wolfSSL_new(s_context);
  Dout(dc::finish, session);
  if (!session)
    THROW_FALERT("wolfSSL_new returned NULL");
  m_read_session = m_write_session = session;
  wolfSSL_SetIOReadCtx(session, this);
  wolfSSL_SetIOWriteCtx(session, this);
  Dout(dc::tls|continued_cf, "wolfSSL_UseSNI(" << session << ", WOLFSSL_SNI_HOST_NAME, \"" << ServerNameIndication << "\", " << ServerNameIndication.length() << ") = ");
  wolfssl_error_code ret = wolfSSL_UseSNI(session, WOLFSSL_SNI_HOST_NAME, ServerNameIndication.c_str(), ServerNameIndication.length());
  Dout(dc::finish, ret);
  if (ret != WOLFSSL_SUCCESS)
    THROW_FALERTC(ret, "wolfSSL_UseSNI([SSL], WOLFSSL_SNI_HOST_NAME, [SNI], [SNILEN])",
        AIArgs("[SSL]", session)("SNI", ServerNameIndication)("SNILEN", ServerNameIndication.length()));
}

int TLS::do_handshake(int& error)
{
  DoutEntering(dc::tls, "TLS::do_handshake()");
  // Try to own the critical area of wolfSSL_connect by incrementing m_session_state.
  int prev_state = m_session_state.fetch_add(s_inside_do_handshake, std::memory_order_relaxed);
  if (is_blocked_or_handshake_finished(prev_state))   // Is (was) there already another thread in the critical area (or is the handshake finished)?
  {
    // Undo the increment and return prev_state to signal that we did not enter wolfSSL_connect.
    m_session_state.fetch_sub(s_inside_do_handshake, std::memory_order_relaxed);
    return prev_state;  // Fuzzy.
  }

  //                            *** wolfSSL_connect CRITICAL AREA ***
  // Only one thread at a time can get here (of the two threads that compete; the read and write thread).
  //
  // If we get here then prev_state has neither inside_do_handshake nor inside_do_handshake2 set
  // (inside_do_handshake2 can only ever be set in m_session_state after the above line when
  // prev_state has inside_do_handshake set, hence is_blocked() returned true). Also post_handshake
  // can not be set because also then is_blocked() returns true.
  //
  // The only possible values of prev_state are therefore: want_write or 0 (meaning, want_read).

  // Before the handshake is finished, there is only one session: read_session and write_session are the same.
  WOLFSSL* session = static_cast<WOLFSSL*>(m_read_session);

  Dout(dc::tls|continued_cf, "wolfSSL_connect(" << session << ") = ");
  wolfssl_error_code ssl_result = wolfSSL_connect(session);
  // By default reset the want_write bit.
  int correction = prev_state & s_want_write;
#ifdef CWDEBUG
  if (ssl_result == WOLFSSL_FATAL_ERROR)
  {
    wolfssl_error_code session_error = wolfSSL_get_error(session, 0);
    Dout(dc::finish, (int)ssl_result << " (" << session_error << ": " << session_error_string(session_error) << ")");
  }
  else
    Dout(dc::finish, ssl_result);
#endif
  if (ssl_result == SSL_SUCCESS)
  {
    // Set m_session_state to post_handshake - and relinquish the inside_do_handshake bit.
    correction -= s_post_handshake - s_inside_do_handshake;
#ifndef HAVE_WRITE_DUP
#error "wolfSSL wasn't configured with --enable-writedup"
#endif
    // Now that the handshake is finished, create a separate handle for writing.
    // m_read_session can only be used for reading after this.
    m_write_session = wolfSSL_write_dup(session);
    prev_state = m_session_state.fetch_sub(correction, std::memory_order_relaxed);
    // Return handshake_finished too, because it was this thread that finished the handshake.
    return prev_state - correction + s_handshake_completed;
  }
  else if (wolfSSL_want_write(session))
  {
    Dout(dc::tls, "wolfSSL_want_write(" << session << ") returned true.");
    // Set m_session_state to want_write - and relinquish the inside_do_handshake bit.
    correction -= s_want_write - s_inside_do_handshake;
  }
  else if (wolfSSL_want_read(session))
  {
    Dout(dc::tls, "wolfSSL_want_read(" << session << ") returned true.");
    // Set m_session_state to 0 (want_read) - and relinquish the inside_do_handshake bit.
    correction += s_inside_do_handshake;
  }
  else
  {
    // A really fatal error.
    error = (ssl_result != WOLFSSL_FATAL_ERROR) ? ssl_result : wolfssl_error_code(wolfSSL_get_error(session, 0));
    // Set m_session_state to handshake_error - and relinquish the inside_do_handshake bit.
    correction -= s_handshake_error - s_inside_do_handshake;
  }
  prev_state = m_session_state.fetch_sub(correction, std::memory_order_relaxed);
  //
  //                         *** End of wolfSSL_connect CRITICAL AREA ***
  return prev_state - correction;
}

int TLS::read(char* plain_text_buffer, ssize_t space, int& error)
{
  DoutEntering(dc::tls, "TLS::read(plain_text_buffer, " << space << ")");
  WOLFSSL* session = static_cast<WOLFSSL*>(m_read_session);
  Dout(dc::tls|continued_cf, "wolfSSL_read(" << session << ", ");
  int ret = wolfSSL_read(session, plain_text_buffer, space);
  if (AI_UNLIKELY(ret < 0))     // WOLFSSL_ERROR_WANT_READ is unfortunately not super unlikely, but fast-track the path that actually read data anyway.
  {
    wolfssl_error_code err = wolfSSL_get_error(session, ret);
    Dout(dc::finish, "plain_text_buffer, " << space << ") = " << ret << " [" << err << "]");
    ASSERT(err != WOLFSSL_ERROR_WANT_WRITE); // WTF? I don't expect this to be possible.
    switch (err)
    {
      case WOLFSSL_ERROR_WANT_READ:
        error = EWOULDBLOCK;
        break;
      case SOCKET_ERROR_E:
        error = m_recv_error;
        break;
      case SOCKET_PEER_CLOSED_E:
        error = ECONNRESET;
        break;
      case BAD_MUTEX_E:
        error = EDEADLK;                // Could be one of several errors (assuming this was a call to pthread_mutex_lock).
        break;
      case BAD_FUNC_ARG:
        error = EINVAL;
        break;
      case WRITE_DUP_READ_E:            // Should never happen.
        error = EPERM;
        break;
      default:
        DoutFatal(dc::core, "Unhandled error " << err);
        break;
    }
    return -1;
  }
  Dout(dc::finish, "{\"" << buf2str(plain_text_buffer, ret) << "\"}, " << space << ") = " << ret);
  return ret;
}

int TLS::write(char const* plain_text, size_t len, int& error)
{
  DoutEntering(dc::tls, "TLS::write(plain_text, " << len << ")");
  WOLFSSL* session = static_cast<WOLFSSL*>(m_write_session);
  Dout(dc::tls|continued_cf, "wolfSSL_write(" << session << ", \"" << buf2str(plain_text, len) << "\", " << len << ") = ");
  int ret = wolfSSL_write(session, plain_text, len);
  Dout(dc::finish, ret);
  // wolfSSL_write returns 0 when the error SOCKET_PEER_CLOSED_E happened, which will be returned by wolfSSL_get_error as well.
  wolfssl_error_code err = AI_UNLIKELY(ret == 0) ? SOCKET_PEER_CLOSED_E : (ret < 0) ? wolfSSL_get_error(session, ret) : 0;
  if (AI_UNLIKELY(err)) // WOLFSSL_ERROR_WANT_WRITE is unfortunately not super unlikely, but fast-track the path that actually wrote data anyway.
  {
    Dout(dc::notice, "ret == " << ret << "; err = " << err);
    ASSERT(err != WOLFSSL_ERROR_WANT_READ); // WTF? I don't expect this to be possible.
    switch (err)
    {
      case WOLFSSL_ERROR_WANT_WRITE:
        error = EWOULDBLOCK;
        break;
      case SOCKET_ERROR_E:
        error = m_send_error;
        break;
      case SOCKET_PEER_CLOSED_E:
        error = ECONNRESET;
        break;
      case BAD_MUTEX_E:
        error = EDEADLK;                // Could be one of several errors (assuming this was a call to pthread_mutex_lock).
        break;
      case BAD_FUNC_ARG:
        error = EINVAL;
        break;
      case WRITE_DUP_WRITE_E:           // Should never happen.
        error = EPERM;
        break;
      default:
        DoutFatal(dc::core, "Unhandled error " << err);
        break;
    }
    return -1;
  }
  return ret;
}

#ifndef HAVE_TLS_EXTENSIONS
#error "WolfSSL wasn't configured with --enable-maxfragment"
#endif
uint32_t TLS::get_max_frag() const
{
  uint32_t max_frag = 0x2000; // FIXME m_read_session->max_fragment;
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
// wolfssl error codes (as returned by wolfSSL_connect, etc)

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
    // wolfSSL_write errors.
    AI_CASE_RETURN(SOCKET_PEER_CLOSED_E);
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
