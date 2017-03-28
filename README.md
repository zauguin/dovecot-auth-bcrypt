bcrypt for Dovecot
==================

Bcrypt password scheme for Dovecot. Based on [rg3's bcrypt wrapper](https://github.com/rg3/bcrypt) for [crypt_blowfish](http://www.openwall.com/crypt/).

We provide the `BCRYPT` hashing scheme which should be compatible with the builtin `BLF-CRYPT` which is not supported on most linux systems.

Build & Install
---------------

    git clone https://github.com/zauguin/dovecot-auth-bcrypt.git
    cd dovecot-auth-bcrypt
    ./build
    sudo ./install

If the build step can not find `dovecot-config`, pass the full path of this file to `./build`.
