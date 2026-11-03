// The libc API jextract binds for D-Bus session buses that listen on an abstract socket, which the JDK cannot name.
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
