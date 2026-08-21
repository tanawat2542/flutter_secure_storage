package com.it_nomads.fluttersecurestorage.ciphers;

/**
 * Chooses whether biometric storage may keep using the pre-isolation Android
 * KeyStore alias. Only a verified legacy AES key with its matching biometric
 * state may remain on that alias.
 */
public final class BiometricKeyAliasPolicy {
    private BiometricKeyAliasPolicy() {}

    public static boolean shouldUseIsolatedAlias(
            boolean wasPreviouslyRecovered,
            boolean hasLegacyAesKey,
            boolean hasLegacyBiometricState
    ) {
        return wasPreviouslyRecovered || !hasLegacyAesKey || !hasLegacyBiometricState;
    }

    public static boolean shouldClearRecoveredStateOnCipherUse(
            boolean usesIsolatedAlias,
            boolean keyWasCreated
    ) {
        return usesIsolatedAlias && keyWasCreated;
    }

    public static boolean shouldBypassMigrationForUnrecoverableRestore(
            boolean savedUsesBiometricCipher,
            boolean currentHasNewIsolatedRecoveryKey
    ) {
        return savedUsesBiometricCipher && currentHasNewIsolatedRecoveryKey;
    }

    public static boolean shouldRetryWithIsolatedAlias(
            boolean canRecoverFromLegacyAlias,
            boolean applicationKeyDecryptionFailed
    ) {
        return canRecoverFromLegacyAlias && applicationKeyDecryptionFailed;
    }
}
