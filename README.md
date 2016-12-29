# mockeagain++

This library was inspired by [agentzh](https://github.com/agentzh)'s
[mockeagain](https://github.com/dndx/mockeagainxx). It does everything
mockeagain does plus the following:

* Full support for mocking the Linux Kernel `epoll` event system (ET and LT).
* Performance improvements on pattern matching and initialization
* High resolution sleep timers
* Various structural refactor to make supporting more event system easy.

The control plane is the same as `mockeagain`, makes switching effortless.

For building, using, controlling and testing, refer to [`mockeagain`'s
documentation](https://github.com/openresty/mockeagain).

## Running with `test-nginx`
It appears that passing `LD_PRELOAD` to `prove` causes Perl to hang. To prevent
this, do the following:

```
$ git clone git@github.com:openresty/test-nginx.git
$ cd test-nginx
test-nginx $ patch -p1 < /path/to/mockeagainxx/test-nginx.patch
test-nginx $ perl Makefile.PL
test-nginx $ make
test-nginx $ sudo make install
```

After that, run tests like this (notice we used `TEST_NGINX_LD_PRELOAD`
instead of `LD_PRELOAD`):

```
lua-nginx-module $ TEST_NGINX_LD_PRELOAD=/home/datong/mockeagainxx/mockeagainxx.so MOCKEAGAIN=rw MOCKEAGAIN_VERBOSE=1 TEST_NGINX_EVENT_TYPE=epoll prove -t t/058-tcp-socket.t
t/058-tcp-socket.t .. ok       
All tests successful.
Files=1, Tests=374, 26 wallclock secs ( 0.15 usr  0.07 sys +  7.45 cusr  2.35 csys = 10.02 CPU)
Result: PASS
```

## Limitations
* `epoll` mocking does **not** support more than one `epoll` instance per
process. This does not causes issue when using with `nginx` as each `nginx`
worker maintains only one `epoll` instance.

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
