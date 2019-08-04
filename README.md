# evio submodule

This repository is a [git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
embedding support for asychronous io events based around epoll.

## I/O device

Each device class has [`evio::FileDescriptor`](Device.h) as virtual base class, which in turn is derived
from [`utils::AIRefCount`](https://github.com/CarloWood/ai-utils/blob/master/AIRefCount.h).

Therefore one should use `boost::intrusive_ptr` to point to newly created device objects. For example,

```
boost::intrusive_ptr<MySocket> device = new MySocket(/* constructor params */);
```

The recommended way to do this is by using `evio::create`:

```
auto device = create<MySocket>(/* constructor params */);
```

which does the same thing as the first line, but with some sanity checks when in debug mode.

Normally, such an object would be deleted as soon as the `boost::intrusive_ptr` is destructed,
however there are exceptions to that rule, see below.

Either during or after construction, the device is associated with an (open) filedescriptor
by calling, usually internally, `FileDescriptor::init(int fd)` with an open filedescriptor `fd`.
Afterwards the member function `is_open()` will return true.

For example,

```
evio::SocketAddress endpoint("/tmp/unix_socket");
evio::OutputStream unix_socket_source;

// Create a UNIX listen socket.
auto listen_socket = evio::create<MyUNIXListenSocket>();
listen_socket->listen(endpoint);
ASSERT(listen_socket->get_flags().is_open());

// Connect a UNIX socket to this listen socket.
auto unix_socket = evio::create<MyUNIXSocket>();
unix_socket->set_source(unix_socket_source);
unix_socket->connect(endpoint);
ASSERT(unix_socket->get_flags().is_open());

// Write some data over the connection.
unix_socket_source << "Hello World" << std::endl;
```

where respectively `listen(endpoint)` and `connect(endpoint)` created new file descriptors and called `FileDescriptor::init` with them.

The filedescriptor of such a device is closed upon destruction of the device or when the user explicitly calls
the member function `close()`. In both cases the virtual function `closed()` is called (and,
in the case of calling `close()`, `is_open()` will return false afterwards).

There are three reasons why a Device is not immediately destroyed once the last `boost::intrusive_ptr`
is destructed:

1. The device is, or is derived from, `PersistentInputFile`. This means that a file path is associated
   with the device that is monitored using [<tt>inotify(7)</tt>](http://man7.org/linux/man-pages/man7/inotify.7.html);
   and as soon as there is something/more to read from that path the device will read it.
   The only way to destroy such an object is by calling `close()`.

2. The device is, or is derived from, `OutputDevice` and there is still data in the output buffer that
   wasn't written yet (and still <em>can</em> be written, of course).

3. The device is, or is derived from, `OutputDevice` and was linked to an `InputDevice` (by calling `set_source(input_device)`).
   Both devices share one buffer. The `OutputDevice` will not be deleted unless its linked `InputDevice` is deleted first.

4. The device is, or is derived from, `InputDevice` and its filedescriptor is still open (that is,
   read() never returned zero). Most notably this is the case for a `ListenSocket` and for
   a `Socket` that has an open (read) connection that wasn't closed yet.

### Device classes

* `File` (input and output).
* `PersistentInputFile` (derived from File).
* `Socket` (input and output).
* `AcceptedSocket<>` (derived from Socket, merely a convenience template class).
* `ListenSocket<AcceptedSocket<MySink, MySource>>` (spawns AcceptedSocket<MySink, MySource> sockets).
* `PipeReadEnd` (input).
* `PipeWriteEnd` (output).

An input device reads from its file descriptor and writes to a Sink.
An output device reads from a Source and writes to its fd.
The Sink and Source must be set seperately by calling the member functions `set_sink(MySink)`
and/or `set_source(MySource)` respectively.

For example,

```
// Some Source and Sink.
evio::OutputStream pipe_source;
MyDecoder pipe_sink;

// Create a pipe.
evio::Pipe pipe;
auto pipe_write_end = pipe.take_write_end();
auto pipe_read_end = pipe.take_read_end();

pipe_write_end->set_source(pipe_source);
pipe_read_end->set_sink(pipe_sink);

pipe_source << "Hello world!" << std::endl;
pipe_write_end->flush_output_device();
```

Note that the `std::endl` causes a "flush", but that this flush is not blocking.
What flushing a `evio::OutputStream` does is tell the library that it may start
writing the contents of the buffer to the file descriptor. Without the `std::endl`
(or `std::flush`) the `"Hello world!"` would have been written to the buffer
but not be written out to the device. The actual writing to the file descriptor
however happens behinds the scenes; this line of code returns immediately.

The line below that calls `flush_output_device()`. This is again non-blocking
and has a different meaning: after this call the device must be considered
closed! What happens is that the library will close the file descriptor as soon
as the output buffer is empty (aka, once the `"Hello world!"` has been written
to the file descriptor). This is different from calling `close_output_device()`
which forcefully closes the file descriptor immediately - as if in an error state.

The `PipeWriteEnd` will not be deleted however until both `pipe_write_end`
went out of scope *and* all data in the output buffer was flushed (written to
the file descriptor), but the file descriptor might be closed before this,
even immediately after returning from `flush_output_device()`.

### Thread safety

Device classes are not thread safe and should only be accessed by
one thread at a time. Under normal usage no mutex is needed however:
one thread would construct the device object and cause a new filedescriptor
to be opened.

As soon as the device is started, callbacks can come in for reading and
writing (aka, methods of the object are called and those access the object).
Normally a device is automatically started and stopped by libevio based
whether data and/or buffer space is available.

The actual read and write events are handled by a thread pool.
For example, in the case of an InputDevice, random threads of a thread pool
will `read(2)` the file descriptor and write the received data into a
buffer. Then check if a complete (decodable) message was received and
if so, pass that message on to the `decode` member function of the `Sink`
object that it was linked to. All of that happens without copying the data:
everything happens while the data remains at the same place in memory
where it was put when reading from the file decriptor.

## Using this git module

The root project should be using
[autotools](https://en.wikipedia.org/wiki/GNU_Build_System_autotools) and
[cwm4](https://github.com/CarloWood/cwm4).

## Example

## Checking out a project that uses the evio submodule.

To clone a project example-project that uses evio simply run:

<pre>
<b>git clone --recursive</b> &lt;<i>URL-to-project</i>&gt;<b>/example-project.git</b>
<b>cd example-project</b>
<b>./autogen.sh</b>
</pre>

The <tt>--recursive</tt> is optional because <tt>./autogen.sh</tt> will fix
it when you forgot it.

Afterwards you probably want to use <tt>--enable-mainainer-mode</tt>
as option to the generated <tt>configure</tt> script.

## Adding the evio submodule to a project

To add this submodule to a project, that project should already
be set up to use [cwm4](https://github.com/CarloWood/cwm4).

Simply execute the following in a directory of that project
where you want to have the <tt>evio</tt> subdirectory:

```
git submodule add https://github.com/CarloWood/evio.git
```

This should clone evio into the subdirectory <tt>evio</tt>, or
if you already cloned it there, it should add it.

Changes to <tt>configure.ac</tt> and <tt>Makefile.am</tt>
are taken care of by <tt>cwm4</tt>, except for linking
which works as usual;

for example, a module that defines a

```
bin_PROGRAMS = foobar
```

would also define

```
foobar_CXXFLAGS = @LIBCWD_R_FLAGS@
foobar_LDADD = ../evio/libevio.la ../threadpool/libthreadpool.la ../threadsafe/libthreadsafe.la ../utils/libutils_r.la ../cwds/libcwds_r.la
```

or whatever the path to `evio/` etc. is, to link with the required submodules,
libraries, and assuming you also use the [cwds](https://github.com/CarloWood/cwds) submodule.

Finally, run

```
./autogen.sh
```

to let cwm4 do its magic, and commit all the changes.

Checkout [ai-evio-testsuite](https://github.com/CarloWood/ai-evio-testsuite)
for an example of a project that uses this submodule.
