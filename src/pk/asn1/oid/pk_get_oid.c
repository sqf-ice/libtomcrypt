/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_DER

typedef struct {
   enum ltc_oid_id id;
   const char* oid;
} oid_table_entry;

static const oid_table_entry pka_oids[] = {
                                              { PKA_RSA,              "1.2.840.113549.1.1.1" },
                                              { PKA_DSA,              "1.2.840.10040.4.1" },
                                              { PKA_EC,               "1.2.840.10045.2.1" },
                                              { PKA_EC_PRIMEF,        "1.2.840.10045.1.1" },
                                              { PKA_PBE_MD2_DES,      "1.2.840.113549.1.5.1" },
                                              { PKA_PBE_MD2_RC2,      "1.2.840.113549.1.5.4" },
                                              { PKA_PBE_MD5_DES,      "1.2.840.113549.1.5.3" },
                                              { PKA_PBE_MD5_RC2,      "1.2.840.113549.1.5.6" },
                                              { PKA_PBE_SHA1_DES,     "1.2.840.113549.1.5.10" },
                                              { PKA_PBE_SHA1_RC2,     "1.2.840.113549.1.5.11" },
                                              { PKA_PBES2,            "1.2.840.113549.1.5.13" },
                                              { PKA_PBKDF2,           "1.2.840.113549.1.5.12" },
                                              { PKA_DES_CBC,          "1.3.14.3.2.7" },
                                              { PKA_RC2_CBC,          "1.2.840.113549.3.2" },
                                              { PKA_DES_EDE3_CBC,     "1.2.840.113549.3.7" },
                                              { PKA_HMAC_WITH_SHA1,   "1.2.840.113549.2.7" },
                                              { PKA_HMAC_WITH_SHA224, "1.2.840.113549.2.8" },
                                              { PKA_HMAC_WITH_SHA256, "1.2.840.113549.2.9" },
                                              { PKA_HMAC_WITH_SHA384, "1.2.840.113549.2.10" },
                                              { PKA_HMAC_WITH_SHA512, "1.2.840.113549.2.11" },
                                              { PKA_PBE_SHA1_3DES,    "1.2.840.113549.1.12.1.3" },
                                              { PKA_AES128_CBC,       "2.16.840.1.101.3.4.1.2" },
                                              { PKA_AES192_CBC,       "2.16.840.1.101.3.4.1.22" },
                                              { PKA_AES256_CBC,       "2.16.840.1.101.3.4.1.42" }
};

/*
   Returns the OID requested.
   @return CRYPT_OK if valid
*/
int pk_get_oid(enum ltc_oid_id id, const char **st)
{
   unsigned int i;
   LTC_ARGCHK(st != NULL);
   for (i = 0; i < sizeof(pka_oids)/sizeof(pka_oids[0]); ++i) {
      if (pka_oids[i].id == id) {
         *st = pka_oids[i].oid;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

/*
   Returns the ltc_oid_id for given OID string.
   @return CRYPT_OK if valid
*/
int pk_get_oid_id(const char *st, enum ltc_oid_id *id)
{
   unsigned int i;
   LTC_ARGCHK(id != NULL);
   for (i = 0; i < sizeof(pka_oids)/sizeof(pka_oids[0]); ++i) {
      if (XSTRCMP(pka_oids[i].oid, st) == 0) {
         *id = pka_oids[i].id;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}
#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
