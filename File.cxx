#include "sys.h"
#include "File.h"
#include <ios>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

namespace evio {

void FileDevice::open(char const* filename, int mode, int prot, int additional_posix_modes)
{
  using std::ios_base;

  int posix_mode;
  flags_t read_write;

  if ((mode & ios_base::app))
    mode |= ios_base::out;

  // At least one of ios_base::in or ios_base::out must be specified.
  ASSERT((mode & (ios_base::in|ios_base::out)) != 0);

  if ((mode & (ios_base::in|ios_base::out)) == (ios_base::in|ios_base::out))
  {
    posix_mode = O_RDWR;
    read_write = FDS_RW;
  }
  else if ((mode & ios_base::out))
    posix_mode = O_WRONLY, read_write = FDS_W;
  else
    posix_mode = O_RDONLY, read_write = FDS_R;

  // Do not call open() on a device that is already initialized with a fd (see IOBase::init) or call close() first.
  ASSERT(!is_open());

  // Meant to be used for things like O_CLOEXEC, O_DIRECTORY, O_DSYNC, O_EXCL, O_NOATIME, O_NOFOLLOW, O_NONBLOCK, O_SYNC, O_TMPFILE, ...
  posix_mode |= additional_posix_modes;

  if ((mode & ios_base::trunc) || mode == ios_base::out)
    posix_mode |= O_TRUNC;
  if ((mode & ios_base::app))
    posix_mode |= O_APPEND;
  if (!(mode & ios_base::in))
    posix_mode |= O_CREAT;

  Dout(dc::system|continued_cf, "open(\"" << filename << "\", " << std::hex << posix_mode << ", " << std::oct << prot << ") = ");
  int fd = ::open(filename, posix_mode, prot);
  Dout(dc::finish|cond_error_cf(fd < 0), fd);

  if (fd < 0)
    // FIXME: throw exception
    return;

  if ((mode & (ios_base::ate|ios_base::app)))
  {
    if (lseek(fd, 0, SEEK_END) == (off_t)-1)
    {
      ::close(fd);
      // FIXME: throw exception
      return;
    }
  }

  init(fd);
}

} // namespace evio
