# evio submodule

This repository is a [git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
embedding a minimum amount of libev for io event support using epoll.

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
