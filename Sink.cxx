#include "sys.h"
#include "Sink.h"

namespace evio {

InputBuffer* Sink::create_buffer(InputDevice* input_device, size_t buffer_full_watermark, size_t max_alloc)
{
  DoutEntering(dc::evio, "Sink::create_buffer(" << input_device << ", " << buffer_full_watermark << ", " << max_alloc << ")");
  m_input_device = input_device;
  InputBuffer* input_buffer = new InputBuffer(input_device, minimum_block_size(), buffer_full_watermark, max_alloc);
  std::istream* istr = dynamic_cast<std::istream*>(this);
  if (istr)
    istr->rdbuf(input_buffer);
  return input_buffer;
}

} // namespace evio
