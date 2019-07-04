//========================================================================
// Cinnabar - RSA-Sign sample code
// Copyright (c) 2019, Pascal Levy
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//========================================================================

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../cinnabar.h"

#define OPTION_REMOVE       0x01

#define MAGIC_0             0x04
#define MAGIC_1             0x00
#define MAGIC_2             0x69
#define MAGIC_3             0xaa

//--------------------------------------------------------------
// Try to find a signature at the end of a file.
//--------------------------------------------------------------

static char const * findSignature(char const * content, size_t content_length) {
    if (content_length > 6) {
        uint8_t const * ptr = (uint8_t const *) content + content_length;
        size_t size = (((unsigned) ptr[-2]) << 8) | ((unsigned) ptr[-1]);
        if (size > 6 && size <= content_length) {
            ptr -= size;
            if (ptr[0] == MAGIC_0 && ptr[1] == MAGIC_1 && ptr[2] == MAGIC_2 && ptr[3] == MAGIC_3) {
                return (char *) ptr;
            }
        }
    }
    return NULL;
}

//--------------------------------------------------------------
// Append a signature at the end of a file.
//--------------------------------------------------------------

static int createSignature(char const * filename, char const * content, size_t content_length, char const * key, unsigned options) {
    int result = EXIT_FAILURE;
    char const * s = findSignature(content, content_length);
    if (s) {
        fprintf(stderr, "%s: error: already signed\n", filename);
    } else {
        CNBR_SIGNATURE signature;
        CnbrStatus status = CnbrSignature(&signature, content, content_length, key);
        if (status == CnbrSuccess) {
            FILE * fp = fopen(filename, "ab");
            if (!fp) {
                fprintf(stderr, "error: cannot write %s\n", filename);
            } else {
                fputc(MAGIC_0, fp);
                fputc(MAGIC_1, fp);
                fputc(MAGIC_2, fp);
                fputc(MAGIC_3, fp);
                fwrite(signature.signature_data, signature.signature_length, 1, fp);
                size_t len = signature.signature_length + 4 + 2;
                fputc((len >> 8) & 0xFF, fp);
                fputc(len & 0xFF, fp);
                fclose(fp);
            }
            result = EXIT_SUCCESS;
            printf("%s: signed\n", filename);
        } else if (status == CnbrInvalidPrivateKey) {
            fprintf(stderr, "%s: error: invalid private key\n", filename);
        } else if (status == CnbrKeyIsTooShort) {
            fprintf(stderr, "%s: error: key is too short\n", filename);
        } else {
            fprintf(stderr, "%s: error: unknown error\n", filename);
        }
        CnbrEraseSignature(&signature);
    }
    return result;
}

//--------------------------------------------------------------
// Verify a signature.
//--------------------------------------------------------------

static int verifySignature(char const * filename, char const * content, size_t content_length, char const * key, unsigned options) {
    char const * signature = findSignature(content, content_length);
    if (!signature) {
        fprintf(stderr, "%s: error: not signed\n", filename);
        return EXIT_FAILURE;
    }
    size_t doc_length = signature - content;
    size_t signature_length = content_length - doc_length - 6;
    CnbrStatus status = CnbrVerifySignature((uint8_t *) signature + 4, signature_length, content, doc_length, key);
    if (status == CnbrSuccess) {
        printf("%s: valid signature\n", filename);
        if (options & OPTION_REMOVE) {
            FILE * fp = fopen(filename, "wb+");
            if (!fp) {
                fprintf(stderr, "%s: error: cannot create file\n", filename);
                return EXIT_FAILURE;
            }
            fwrite(content, doc_length, 1, fp);
            fclose(fp);
        }
    } else if (status == CnbrInvalidPrivateKey) {
        fprintf(stderr, "%s: error: invalid public key\n", filename);
    } else if (status == CnbrInvalidSignature) {
        fprintf(stderr, "%s: error: invalid signature\n", filename);
    } else {
        fprintf(stderr, "%s: error: unknown error\n", filename);
    }
    return EXIT_SUCCESS;
}

//--------------------------------------------------------------
// Load a file into a memory buffer. For convenience, the memory
// buffer is null terminated, even if the file content is not actually
// a string. The caller is responsible for freeing the buffer.
//--------------------------------------------------------------

static char * loadFileContents(char const * filename, size_t * psize) {
    FILE * fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "%s: error: file not found\n", filename);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    char * content = malloc(size + 1);
    rewind(fp);
    if (fread(content, 1, size, fp) != size) {
        fprintf(stderr, "%s: error: cannot read file\n", filename);
        fclose(fp);
        free(content);
        return NULL;
    }
    fclose(fp);
    content[size] = '\0';
    if (psize) {
        *psize = size;
    }
    return content;
}

//--------------------------------------------------------------
// Print usage on the standard error output.
//--------------------------------------------------------------

static void usage() {
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "    rsa-sign sign <path to private key> <files...>\n");
    fprintf(stderr, "    rsa-sign verify [-r] <path to public key> <files...>\n\n");
    fprintf(stderr, "options:\n");
    fprintf(stderr, "    -r     if the signature is valid, remove it\n");
    fprintf(stderr, "\n");
}

//--------------------------------------------------------------
// Entry point.
//--------------------------------------------------------------

int main(int argc, const char * argv[]) {
    int (* fnc)(char const *, char const *, size_t, char const *, unsigned) = NULL;
    unsigned options = 0;

    // Determine if we are generating or verifying a signature.

    if (argc >= 2) {
        if (!strcmp(argv[1], "sign")) {
            fnc = createSignature;
        } else if (!strcmp(argv[1], "verify")) {
            fnc = verifySignature;
        }
    }
    if (!fnc) {
        usage();
        return EXIT_FAILURE;
    }

    // Parse options.

    int ndx = 2;
    while (ndx < argc && argv[ndx][0] == '-') {
        char const * opt = argv[ndx] + 1;
        for ( ; ; ) {
            char c = *opt++;
            if (c == '\0') {
                break;
            } else if (c == 'r' && fnc == verifySignature) {
                options |= OPTION_REMOVE;
            } else {
                usage();
                return EXIT_FAILURE;
            }
        }
        ndx++;
    }

    // Read the private/public key file.

    if (ndx >= argc) {
        usage();
        return EXIT_FAILURE;
    }

    size_t key_length;
    char * key = loadFileContents(argv[ndx], &key_length);
    if (!key) {
        return EXIT_FAILURE;
    }

    // Process the files, if any.

    int errors = 0;
    while (++ndx < argc) {
        size_t content_length;
        char * content = loadFileContents(argv[ndx], &content_length);
        if (content) {
            int r = fnc(argv[ndx], content, content_length, key, options);
            if (r != EXIT_SUCCESS) {
                errors++;
            }
            free(content);

        } else {
            errors++;
        }
    }

    free(key);
    return (errors > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}

//========================================================================
