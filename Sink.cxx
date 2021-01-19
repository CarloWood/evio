#include "sys.h"
#include "Sink.h"
#include <limits>

#ifdef CWDEBUG
NAMESPACE_DEBUG_CHANNELS_START
channel_ct endofmsg("ENDOFMSG");
channel_ct decoder("DECODER");
NAMESPACE_DEBUG_CHANNELS_END
#endif

namespace evio {

void Sink::initialize(InputDevice* input_device)
{
  m_input_device = input_device;
  m_content_length = c_undefined;
  m_total_len = 0;
  m_next_decoder = nullptr;
}

void Sink::initialize_content_length()
{
  DoutEntering(dc::decoder, "Sink::initialize_content_length()");
  if (m_content_length == Sink::c_undefined && m_get_content_length)
  {
    m_content_length = m_get_content_length();
    // m_get_content_length must return a non-negative value.
    ASSERT(m_content_length >= 0);
  }
}

InputBuffer* Sink::create_buffer(InputDevice* input_device, size_t buffer_full_watermark, size_t max_alloc)
{
  DoutEntering(dc::evio, "Sink::create_buffer(" << input_device << ", " << buffer_full_watermark << ", " << max_alloc << ")");
  initialize(input_device);
  InputBuffer* input_buffer = new InputBuffer(input_device, minimum_block_size(), buffer_full_watermark, max_alloc);
  std::istream* istr = dynamic_cast<std::istream*>(this);
  if (istr)
    istr->rdbuf(input_buffer);
  return input_buffer;
}

//static
constexpr size_t Sink::c_undefined;

} // namespace evio
