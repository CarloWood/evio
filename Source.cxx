#include "sys.h"
#include "Source.h"
#include "OutputDevice.h"
#include "debug.h"

namespace evio {

void Source::start_output_device()
{
  DoutEntering(dc::evio, "Source::start_output_device() [" << m_output_device << ']');
  FileDescriptor::state_t::wat state_w(m_output_device->m_state);
  if (!state_w->m_flags.is_active_output_device())
    m_output_device->start_output_device(state_w);
}

} // namespace evio
