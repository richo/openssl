set -ex
make all
cc -g -o poc -Iinclude poc.c libssl.a libcrypto.a -ldl
