# evio submodule

This repository is a [git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
embedding a minimum amount of [libev](http://software.schmorp.de/pkg/libev.html) for io event support using epoll.

## I/O device

Each device class has [`evio::IOBase`](Device.h) as virtual base class, which in turn is derived
from [`utils::AIRefCount`](https://github.com/CarloWood/ai-utils/blob/master/AIRefCount.h).

Therefore one should use `boost::intrusive_ptr` to point to newly created device objects. For example,

```
boost::intrusive_ptr<Device<IO>*> device = new Device<IO>(/* constructor params */);
```

The recommended way to do this is by using `evio::create`:

```
auto device = create<Device<IO>>(/* constructor params */);
```

which does the same thing as the first line.

Normally, such an object would be deleted as soon as the `boost::intrusive_ptr` is destructed,
however there are exceptions to that rule, see below.

Either during or after construction, the device is associated with an (open) filedescriptor
by calling, usually internally, `IOBase::init(int fd)` with an open filedescriptor `fd`.
Afterwards the member function `is_open()` will return true. The filedescriptor is closed
upon destruction of the device or when the user explicitly calls the member function `close()`.
In both cases the virtual function `closed()` is called (and, in the case of calling `close()`,
`is_open()` will return false).

There are three reasons why a Device is not immediately destroyed once the last `boost::intrusive_ptr`
is destructed:

1. Device is, or is derived from, `PersistentInputFile`. This means that a file path is associated
   with the device that is monitored using [<tt>inotify(7)</tt>](http://man7.org/linux/man-pages/man7/inotify.7.html);
   and as soon as there is something/more to read from that path the device will read it.
   The only way to destroy such an object is by calling `close()`.

2. `IO` is, or is derived from, `OutputDevice` and there is still data in the output buffer that
   wasn't written yet (and still <em>can</em> be written, of course).

3. `IO` is, or is derived from, `LinkOutputDevice` and the `InputDevice` that it shares the buffer
   with wasn't deleted yet.

4. `IO` is, or is derived from, `InputDevice` and its filedescriptor is still open (that is,
   read() never returned zero). Most notably this is the case for a `ListenSocket` and for
   a `Socket` that has an open (read) connection that wasn't closed yet.

### Device classes

* `File<INPUT>` or `File<OUTPUT>`.
* `PipeEnd<INPUT>` or `PipeEnd<OUTPUT>`.
* `Socket<INPUT, OUTPUT>`.
* `ListenSocket<Socket<INPUT, OUTPUT>>`.

In all cases `INPUT` and `OUTPUT` become a base class of the device.
`INPUT` must be derived from `InputDevice`, while `OUTPUT` must be
derived from `OutputDevice`.

### Thread safety

Device classes are not thread safe and should only be accessed by
one thread at a time. Under normal usage no mutex is needed however:
one thread would construct the device object and cause a new filedescriptor
to be opened. This filedescriptor is registered with libev, which requires
also a one-thread-at-a-time treatment, but that has been taken care of
by locking `EventLoopThread::m_loop_mutex` internally whenever libev call
is performed that manipulates the `loop` object.

As soon as the device is added to libev, callbacks can come in for
reading and writing (aka, methods of the object are called and those
access the object). read_from_fd

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

<pre>
git submodule add https://github.com/CarloWood/evio.git
</pre>

This should clone evio into the subdirectory <tt>evio</tt>, or
if you already cloned it there, it should add it.

Changes to <tt>configure.ac</tt> and <tt>Makefile.am</tt>
are taken care of by <tt>cwm4</tt>, except for linking
which works as usual;

for example, a module that defines a

<pre>
bin_PROGRAMS = foobar
</pre>

would also define

<pre>
foobar_CXXFLAGS =
foobar_LDADD = ../evio/libev-4.24/libev.la
</pre>

or whatever the path to `evio/` etc. is, to link with the required submodules,
libraries, and assuming you also use the [cwds](https://github.com/CarloWood/cwds) submodule.

Finally, run

<pre>
./autogen.sh
</pre>

to let cwm4 do its magic, and commit all the changes.

Checkout [ai-evio-testsuite](https://github.com/CarloWood/ai-evio-testsuite)
for an example of a project that uses this submodule.
