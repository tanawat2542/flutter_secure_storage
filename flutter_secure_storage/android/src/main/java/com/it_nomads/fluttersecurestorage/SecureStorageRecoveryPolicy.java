package com.it_nomads.fluttersecurestorage;

/** Recovery decisions that must not broaden secure-storage reset behavior. */
final class SecureStorageRecoveryPolicy {
    private SecureStorageRecoveryPolicy() {
    }

    /**
     * Restored RSA-backed storage still honors resetOnError when its wrapped
     * application key cannot be decrypted. Biometric storage has its own
     * isolated-alias recovery path and must not be reset here.
     */
    static boolean shouldUseResetOnErrorForInitializationFailure(
            boolean biometricStorage,
            boolean applicationKeyDecryptionFailed
    ) {
        return !biometricStorage && applicationKeyDecryptionFailed;
    }

    /**
     * A caller explicitly deleting an invalidated namespace is a recovery
     * action. Normal reads and writes must continue returning the error.
     */
    static boolean shouldForceResetAfterInitializationFailure(
            String method,
            boolean keyInvalidated
    ) {
        return keyInvalidated && ("delete".equals(method) || "deleteAll".equals(method));
    }
}
