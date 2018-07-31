# evio submodule

This repository is a [git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
embedding a minimum amount of [libev](http://software.schmorp.de/pkg/libev.html) for io event support using epoll.

## I/O device

Each device class has [`evio::IOBase`](Device.h) as virtual base class, which in turn is derived from [`utils::AIRefCount`](../utils/AIRefCount.h).

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

Either after or during construction the device is associated with an (open) filedescriptor
(by calling, usually internally, `IOBase::init(int fd)` with an open filedescriptor `fd`,
after which the member function `is_open()` will return true). The filedescriptor is closed
upon destruction of the device or when the user explicitly calls the member function `close()`.
In both cases the virtual function `closed()` is called, and `is_open()`
returns false (after calling `close()`, not after destruction of course ;).

There are three reasons why a Device is not immediately destroyed once the `boost::intrusive_ptr`
is destructed:

1. Device is (derived from) `PersistentInputFile`. This means that a file path is associated
   with the device that is monitored using <tt>inotify(7)</tt>; and as soon as there is
   something/more to read from that path the device will read it. The only way to destroy
   such an object is by calling `close()`.

2. `IO` is (derived from) `OutputDevice` and there is still data in its buffer that wasn't
   written yet (and still <em>can</em> be written, of course).

3. `IO` is (derived from) `LinkOutputDevice` and the `InputDevice` that shares the buffer
   wasn't deleted yet.

### Device classes

* `File<IO>`

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

Checkout [ai-statefultask-testsuite](https://github.com/CarloWood/ai-statefultask-testsuite)
for an example of a project that uses this submodule.
