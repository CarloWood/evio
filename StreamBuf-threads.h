#pragma once

namespace evio {

// Thread-safety
// =============
//
// When using the streambuf directly, or through istream/ostream or their iterators,
// the get area (pointers and content) are used by everything "Reading" (istream),
// while the put area (pointers and content) are used by everything "Writing" (ostream).
// No mutex locking occurs. However, the get area and put area are never moved;
// if a get area is empty or a put area is full, virtual functions are called to
// deal with this.
//
// To keep things simple, lets just look at one side and assume we are the thread
// that writes to the put area. In that case we know that no other thread is
// is accessing the put area (the user is responsible for that) and we can do
// whatever we want with the put area. However, another thread might be accessing
// the get area through (say) an istream which, completely out of our control,
// might write to and bump gptr. Therefore we are not allowed to either read or write gptr.
// However, as long as there is no other reading (get) thread in one of our virtual
// functions then neither eback nor egptr will be changed, so it is safe to read
// those values.
//
// Likewise when we are the thread that reads from the get area then we can do
// anything we want with the get area, but we may never read or write pptr.
// As long as there is no thread in one of our virtual functions that change
// pbase and/or epptr then we're allowed to read those however.
//
// Finally, if we don't know what thread we are in because we're in some accessor,
// then we may only read eback, egptr, pbase and/or epptr - and only as long
// as there are no threads in one of our virtual functions that change those.
//
// Whether or not locking a mutex is necessary while changing a get or put
// area therefore depends on whether or not it is necessary to read the begin
// or end of that area in the opposing thread.
//
// The following actions are required:
//
// - Check if the buffer is empty (buffer_empty).
// - Get an estimate of the number of bytes in the buffer (showmanyc).
// - Check if the buffer contains more than low water-mark bytes.
// - Check if the buffer is full.
// - Check if the put and get area point to the same MemoryBlock,
// - and if so, check if there is more data beyond egptr.
// - Move the get area to the next MemoryBlock and release the old one (underflow).
// - Append a new block to the end of the list and move the put area to it (overflow).
// - Prepend a new block in front of the list and move the get area to it (pbackfail).

// One of the most complex problems that I had to solve for this library is
// starting and stopping a device (file descriptor) as function of whether or
// not the buffer is empty.
//
// Lets say we are reading from the buffer and writing to the file descriptor,
// the other way around is symmetrical: there is little or no difference.
//
// In this case we want the output device to be started when there is data
// in the buffer, and to be stopped when there is no data in the buffer.
//
// As above, we assume that there is only one thread at a time that writes
// to the buffer (called the "PutThread"), and only one thread that reads
// from the buffer (called the "GetThread"), but reading and writing might
// happen concurrently.
//
// Of course, the library needs to be entered at all in order for the device
// to be started or stopped; when reading from the buffer this is easy: even
// when we read with strictly std::streambuf code, as soon as the get area
// becomes empty the virtual function streambuf::underflow(), which calls
// the appropriate StreamBuf::underflow_a() function, is called. When writing
// to the buffer with strictly std::streambuf code, the user has to explicitly
// flush the ostream (which causes a call to the virtual function Buf2Dev::sync()
// which in turn calls OutputDevice::sync()).
//
// The buffer is considered empty when gptr == pptr and testing that from
// either PutThread or GetThread is actually Undefined Behavior because
// we cannot put a mutex around the strictly std::streambuf initiated bumps
// of gptr and pptr. Nevertheless, we (have to) assume that reading these
// values are atomic, as should be the case on at least x86_64 architectures.
// Nevertheless, as soon as we read either value, they might already change
// again; fortunately with a structure: only the GetThread will bump gptr
// and only the PutThread will bump pptr.
//
// Under normal circumstances (ignoring putbacks for the moment) the "buffer empty"
// state transition is as follows:
//
//                     ---PutThread-->
//      [buffer empty]                 [buffer not empty]
//                     <--GetThread---
//
// Therefore (using utils::FuzzyBool terminology) the PutThread will
// see the values True and WasFalse for 'buffer empty', while the GetThread
// will see the values WasTrue and False.
//
// The actual act of starting or stopping a device is protected by a mutex
// (there is only one thread at a time (allowed) in libev). In order to
// assure that we will never end up in a prolongued state where the buffer
// is not empty but the device is stopped (and to a lesser degree where the
// buffer is empty but the device is started, as that will correct itself)
// we need to test if the buffer is actually (still) empty inside the critical
// area of libev (prior to stopping the device) in the case the original
// test resulted in WasTrue.
//
// Consider reading from a buffer till it is empty and stopping the device,
// followed by writing to the buffer and starting the device (not race):
//
//     empty_buffer(GetThread)          !empty_buffer(PutThread)
//
// Time
//  |  (Buffer not empty is assumed
//  |   based on the fact that the
//  V   GetThread is running)
//
//     (read from buffer)
//     buffer_empty() == WasTrue
//
//     -->--(libev critical area)
//     if (buffer_empty().
//         is_momentary_true())
//       stop()
//     --<--
//
//                                      False (so empty_buffer returned True).
//                                      (write to buffer and sync)
//                                      !buffer_empty() == WasTrue
//
//                                      -->--
//                                      if ((!buffer_empty()).
//                                          is_momentary_true())
//                                        start()
//                                      --<--
//
// This obviously results in a state where the buffer is not empty
// and the device is started. Now lets try to obtain a state where
// the buffer is not empty and the device is stopped.
//
// That means that the critical area part on the right has to be
// moved before the critical area part on the left, or else the
// critical area part on the right is the last code executed and
// it is impossible to end with !buffer_empty() true without
// calling start(). However then also the '(write to buffer and sync)'
// must go before the critial area part on the left, which will
// cause the 'buffer_empty().is_momentary_true()' in that part
// to fail and stop() not being called unless we push the
// 'write to buffer' (bump pptr) to above '(read from buffer)',
// but in that case the buffer is thus actually empty.
// So this seems to work.
//
// We can do another attempt by using the image above, but have
// the GetThread empty the buffer before the PutThread can execute
// the !buffer_empty() test in the critical area so that start()
// isn't called, but well, in that case the buffer is thus also
// actually empty at the end.
//
// Finally, you can try to halt the GetThread right before calling
// stop() (so it already tested buffer_empty().is_momentary_true())
// and then do something that makes the buffer non-empty, after
// which the GetThread will still call stop(). But that 'doing
// something' is a '((write to buffer and sync)' in the PutThread,
// the PutThread then will hang right before the critical area
// until the GetThread executed stop() and left the critical area,
// after which the PutThread will start() the device again.
//

// The methods of this type may only be called by at most one thread at
// a time, during which the std::streambuf may also not be used for writing
// by another thread by means of an ostream, ostream::iterator or otherwise.
// Aka, no other thread maybe be updating pptr.
struct PutThread
{
};

// The methods of this type may only be called by at most one thread at
// a time, during which the std::streambuf may also not be used for reading
// by another thread by means of an istream, istream::iterator or otherwise.
// Aka, no other thread maybe be updating gptr.
struct GetThread
{
};

// The methods of this type may be called by any thread at any time.
// Aka, these methods are thread-safe. All of these methods are accessors.
struct AnyThread
{
};

// The methods of this type may only be called by one and the same thread
// while no other thread even knows about this object (won't call any of
// the other methods).
// This can be used during initialization of an object (ie, construction
// and following initialization) or in debug cases where we take a race
// for granted.
//
// SingleThread satisfies the requirements of both, PutThread and GetThread
// and may therefore use methods that require either of those. This is
// achieved by deriving SingleThread from both, so that it can be passed
// to such functions.
//
struct SingleThread : public PutThread, public GetThread
{
};

} // namespace evio
