# mockeagain++

This library was inspired by [agentzh](https://github.com/agentzh)'s
[mockeagain](https://github.com/openresty/mockeagain). It does everything
mockeagain does plus the following:

* Full support for mocking the Linux Kernel `epoll` event system (ET and LT).
* Performance improvements on pattern matching and initialization
* High resolution sleep timers
* Various structural refactor to make supporting more event system easy.
* Support mocking on dynamic number of file descriptors (no more
`worker_connections 1024` necessary!)

The control plane is the same as `mockeagain`, makes switching effortless.

For building, using, controlling and testing, refer to [`mockeagain`'s
documentation](https://github.com/openresty/mockeagain).

## Limitations
* `epoll` mocking does **not** support more than one `epoll` instance per
process. This does not causes issue when using with `nginx` as each `nginx`
worker maintains only one `epoll` instance.
* Mocking is only active on non blocking stream sockets. The way `mockeagain++`
detects this condition is by hooking `accept4()`, `socket()` and `ioctl()`
system calls and try to interpret state of the file descriptor by observing.
`fcntl()` is currently not implemented due to the complexity involved in
hooking it (different sizes of third argument). `nginx` does not uses
`fcntl()`.

## Copyright & License

`mockeagain++` is licensed under the MIT license.

Copyright 2016-2017 \<Datong Sun (dndx@idndx.com)\>

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
