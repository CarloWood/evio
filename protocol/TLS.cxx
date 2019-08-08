#include "sys.h"
#include "TLS.h"
#include "utils/debug_ostream_operators.h"
#include <libcwd/buf2str.h>
#include <alloca.h>

extern "C" {

#if 0
static void tls_audit_log_function(gnutls_session_t UNUSED_ARG(session), char const* message)
{
  // Message already contain a newline.
  Dout(dc::warning|nonewline_cf, "GNUTLS audit: " << message);
}

static void tls_log_function(int UNUSED_ARG(level), char const* message)
{
  // Message contains sometimes a newline.
  size_t len = std::strlen(message);
  bool has_new_line = message[len - 1] == '\n';
  if (has_new_line)
  {
    char* buf = reinterpret_cast<char*>(alloca(len));
    buf[len - 1] = 0;
    Dout(dc::gnutls, std::strncpy(buf, message, len - 1));
  }
  else
    Dout(dc::gnutls, message);
}

static int system_recv_timeout(gnutls_transport_ptr_t ptr, unsigned int ms)
{
  fd_set rfds;
  struct timeval tv;
  int fd = (long)ptr;

  DoutEntering(dc::notice, "system_recv_timeout(" << fd << ", " << ms << ")");

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  tv.tv_sec = 0;
  tv.tv_usec = ms * 1000;
  while (tv.tv_usec >= 1000000) {
          tv.tv_usec -= 1000000;
          tv.tv_sec++;
  }

  return select(fd + 1, &rfds, NULL, NULL, &tv);
}

static ssize_t system_write(gnutls_transport_ptr_t ptr, void const* data, size_t data_size)
{
  evio::InputDevice* input_device = static_cast<evio::InputDevice*>(ptr);
  DoutEntering(dc::notice|continued_cf, "system_write(" << input_device << ", \"" << libcwd::buf2str((char const*)data, data_size) << "\") = ");
  ssize_t ret = send(input_device->get_fd(), data, data_size, 0);
  Dout(dc::finish|cond_error_cf(ret < 0), ret);
  return ret;
}

static ssize_t system_read(gnutls_transport_ptr_t ptr, void* data, size_t data_size)
{
  evio::OutputDevice* output_device = static_cast<evio::OutputDevice*>(ptr);
  DoutEntering(dc::notice|continued_cf, "system_read(" << output_device << ", {")
  ssize_t ret = recv(output_device->get_fd(), data, data_size, 0);
  Dout(dc::finish|cond_error_cf(ret < 0), libcwd::buf2str((char*)data, ret < 0 ? 0 : data_size) << "}) = " << ret);
  return ret;
}
#endif

} // extern "C"

#if defined(CWDEBUG) && !defined(DOXYGEN)
NAMESPACE_DEBUG_CHANNELS_START
channel_ct gnutls("GNUTLS");
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {
namespace protocol {

struct gnutls_error_codes
{
  int mCode;

  gnutls_error_codes(int code) : mCode(code) { }
  operator int() const { return mCode; }
};

std::error_code make_error_code(gnutls_error_codes);

} // namespace protocol
} // namespace evio

// Register evio::gnutls_error_codes as valid error code.
namespace std {

template<> struct is_error_code_enum<evio::protocol::gnutls_error_codes> : true_type { };

} // namespace std

namespace evio {
namespace protocol {

//gnutls_certificate_credentials_t TLS::s_xcred;
//int TLS::s_debug_level = 0;

#if 0
//static
void TLS::set_debug_level(int debug_level)
{
  s_debug_level = debug_level;
#ifndef CWDEBUG
  if (s_debug_level > 0)
    std::cerr << "Warning: TLS::set_debug_level(" << debug_level << ") called without CWDEBUG being defined." << std::endl;
#endif
}
#endif

std::once_flag TLS::s_flag;
void TLS::global_tls_initialization()
{
  DoutEntering(dc::notice, "evio::protocol::TLS::global_tls_initialization()");

#if 0
#ifdef CWDEBUG
  gnutls_global_set_audit_log_function(tls_audit_log_function);
  gnutls_global_set_log_function(tls_log_function);
#endif
  if (s_debug_level > 0)
  {
    gnutls_global_set_log_level(s_debug_level);
    Dout(dc::gnutls|dc::notice, "GNU TLS debug level set to " << s_debug_level);
  }

  // X509 stuff.
  gnutls_certificate_allocate_credentials(&s_xcred);
  // Sets the system trusted CAs for Internet PKI.
  gnutls_error_codes ret = gnutls_certificate_set_x509_system_trust(s_xcred);
  if (ret < 0)
    THROW_FALERTC(ret, "gnutls_certificate_set_x509_system_trust");
  else
    Dout(dc::gnutls, "Number of trusted system certificates processed: " << ret);
#endif
}

TLS::TLS() : m_session(nullptr)
{
  DoutEntering(dc::gnutls, "TLS::TLS() [" << this << "]");
  std::call_once(s_flag, global_tls_initialization);
}

TLS::~TLS()
{
  DoutEntering(dc::gnutls, "TLS::~TLS()");
  //gnutls_deinit(m_session);
}

void TLS::session_init(char const* http_server_name, size_t http_server_name_length)
{
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
// gnutls error codes (as returned by gnutls_certificate_set_x509_system_trust(3), etc)

namespace {

struct GNUTLSErrorCategory : std::error_category
{
  char const* name() const noexcept override;
  std::string message(int ev) const override;
};

char const* GNUTLSErrorCategory::name() const noexcept
{
  return "gnutls";
}

std::string GNUTLSErrorCategory::message(int ev) const
{
  return "huh"; //gnutls_strerror(ev);
}

GNUTLSErrorCategory const theGNUTLSErrorCategory { };

} // namespace

std::error_code make_error_code(gnutls_error_codes code)
{
  return std::error_code(static_cast<int>(code), theGNUTLSErrorCategory);
}

} // namespace protocol
} // namespace evio
