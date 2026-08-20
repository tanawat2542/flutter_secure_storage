package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;

import java.security.Key;

import javax.crypto.Cipher;

public interface KeyCipher {
    // For symmetric keys
    Cipher getCipher(Context context) throws Exception;

    /**
     * Whether this cipher can recover from a verified application-key
     * decryption failure by switching away from its legacy shared alias.
     */
    default boolean canRecoverFromApplicationKeyDecryptionFailure() {
        return false;
    }

    /** Marks the current namespace to use its isolated alias on retry. */
    default void markForIsolatedAliasRecovery() {}

    void deleteKey() throws Exception;

    // For asymmetric keys
    byte[] wrap(Key key) throws Exception;
    Key unwrap(byte[] wrappedKey, String algorithm) throws Exception;
}
