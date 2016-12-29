/*
 * Copyright 2016-2017 <Datong Sun (dndx@idndx.com)>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>

static int verbose;

#ifndef NDEBUG
    #define debug(...) \
        do { \
            fprintf(stderr, "mockeagainxx: [DEBUG] "); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__); \
        } while (0)
#else
        #define debug(...)
#endif /* !NDEBUG */

#define fatal(...) \
    do { \
        fprintf(stderr, "mockeagainxx: [FATAL] "); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } while (0)

#define log(...) \
    do { \
        if (verbose) { \
            fprintf(stderr, "mockeagainxx: [LOG] "); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__); \
        } \
    } while (0)

#endif /* !UTILS_H */
