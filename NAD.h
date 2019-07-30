// The following public methods can cause the deletion of a device object (an object derived from FileDescriptor):
//
// FileDescriptor::close_input_device           [virtual] Implemented by InputDevice::close_input_device (see below). The default does nothing.
// FileDescriptor::close_output_device          [virtual] Implemented by OutputDevice::close_output_device (see below). The default does nothing.
// FileDescriptor::close                        Calls the above two functions.
//
// InputDevice::close_input_device              [virtual final] Closes the InputDevice.
// OutputDevice::close_output_device            [virtual final] Closes the OutputDevice.
// OutputDevice::flush_output_device            Bring OutputDevice into the state flushing.
//
// File::close                                  Clear m_filename and call FileDescriptor::close.
//
// The calls to InputDevice::close_input_device and OutputDevice::close_output_device must cause a call to allow_deletion()
// if the device is in the state is_r_added() or is_w_added() respectively (an I/O device that is derived from both and
// has both FDS_R_ADDED and FDS_W_ADDED set might cause two calls to allow_deletion(), but only the second call can
// cause a deletion). The call to OutputDevice::flush_output_device must cause a call to allow_deletion() if the device
// is in state is_w_added() and not is_active_output_device(). For more details see README.devices.
//
// The call to allow_deletion() however, might immediately delete the device if it deletes the last reference (count) to the object.
// If that is undesired, then keep the returned object alive until the device is no longer needed.
// For example,
//
// {
//   auto keep_alive = device->close();
//   // Use device still
// } // Destroy keep_alive and thus (maybe) device.
//
// In fact, the returned object can be converted to a bool to test if
// the device was closed and therefore might be deleted; for example,
//
// {
//   auto was_closed = device->flush_output_device();
//   if (!was_closed)
//   {
//     ...
//   }
// }
//
// Or directly,
//
// if (!device->flush_output_device())
// {
//   ...
// }
//
// Calling flush_output_device() will eventually cause a close and delete though, so there isn't much
// difference between flush_output_device() and close_output_device(). The difference is that the latter
// closes the device immediately while the former first flushes the contents of the buffer before closing.
//
//
// The following protected member functions also might cause a call to allow_deletion() (namely when
// the state goes from ADDED to not ADDED, see README.devices):
//
// FileDescriptor::close
// InputDevice::remove_input_device
// InputDeviceEventsHandler::close_input_device
//
// The interface of these is different. For example, you should call them as follows:
//
// NAD_CALL(device->remove_input_device);

#pragma once

// (Private/)Protected interface

#define NAD_DECL(funcname, ...) void funcname(int& need_allow_deletion, ## __VA_ARGS__)
#define NAD_DECL_BOOL(funcname, ...) bool funcname(int& need_allow_deletion, ## __VA_ARGS__)
#define NAD_DECL_UNUSED_ARG(funcname, ...) void funcname(int& UNUSED_ARG(need_allow_deletion), ## __VA_ARGS__)
#define NAD_DECL_CWDEBUG_ONLY(funcname, ...) void funcname(int& CWDEBUG_ONLY(need_allow_deletion), ## __VA_ARGS__)

#define NAD_CALL(funcname, ...) funcname(need_allow_deletion, ## __VA_ARGS__)

#define NAD_DoutEntering_ARG0 "{" << need_allow_deletion << "}, "
#define NAD_DoutEntering_ARG "{" << need_allow_deletion << "}"

// Public interface

#define NAD_DECL_PUBLIC(funcname, ...) RefCountReleaser funcname(__VA_ARGS__)
#define NAD_PUBLIC_BEGIN RefCountReleaser nad_rcr;
#define NAD_CALL_FROM_PUBLIC(funcname, ...) \
  do { \
    int need_allow_deletion = 0; \
    funcname(need_allow_deletion, ## __VA_ARGS__); \
    if (need_allow_deletion > 0) nad_rcr.add(this); \
    if (need_allow_deletion > 1) allow_deletion(need_allow_deletion - 1); \
  } while(0)
#define NAD_PUBLIC_END return nad_rcr;

#define NAD_PUBLIC_CALL(funcname, ...) funcname(__VA_ARGS__)
#define NAD_CALL_PUBLIC(funcname, ...) nad_rcr += funcname(__VA_ARGS__)
