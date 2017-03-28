#include <dovecot/config.h>           // We don't want to define HAS_CONFIG_H
#include <dovecot/lib.h>              // for dovecot
#include <dovecot/password-scheme.h>  // for password_encoding::PW_ENCODING_...
#include <stdio.h>                    // for size_t
#include <string.h>                   // for strlen
#include "bcrypt.h"                   // for BCRYPT_HASHSIZE, bcrypt_checkpw

#define STRINGIFY(x) #x

static void scheme_generate(const char *plaintext,
                            const char *user ATTR_UNUSED,
                            const unsigned char **raw_password_r,
                            size_t *size_r) {
  char salt[BCRYPT_HASHSIZE];
  char *hash = (char *)t_malloc(BCRYPT_HASHSIZE);
  bcrypt_gensalt(password_scheme_encryption_rounds, salt);
  bcrypt_hashpw(plaintext, salt, hash);
  *size_r = strlen(hash);
  *raw_password_r = (const unsigned char *)hash;
}

static int scheme_verify(const char *plaintext,
                         const char *user ATTR_UNUSED,
                         const unsigned char *raw_password,
                         size_t size ATTR_UNUSED,
                         const char **error_info ATTR_UNUSED) {
  return !bcrypt_checkpw(plaintext, (const char *)raw_password);
}

const struct password_scheme password_scheme
    = {"BCRYPT", PW_ENCODING_NONE, 0, scheme_verify, scheme_generate};

struct module;
void auth_bcrypt_plugin_init(struct module *the_module ATTR_UNUSED);
void auth_bcrypt_plugin_init(struct module *the_module ATTR_UNUSED) {
  password_scheme_register(&password_scheme);
}

void auth_bcrypt_plugin_deinit(void);
void auth_bcrypt_plugin_deinit(void) {
  password_scheme_unregister(&password_scheme);
}

const char *password_scheme_version = DOVECOT_ABI_VERSION;
