package com.it_nomads.fluttersecurestorage.ciphers;

/**
 * Chooses whether biometric storage may keep using the pre-isolation Android
 * KeyStore alias. Only a verified legacy AES key with its matching biometric
 * state may remain on that alias.
 */
final class BiometricKeyAliasPolicy {
    private BiometricKeyAliasPolicy() {}

    static boolean shouldUseIsolatedAlias(
            boolean wasPreviouslyRecovered,
            boolean hasLegacyAesKey,
            boolean hasLegacyBiometricState
    ) {
        return wasPreviouslyRecovered || !hasLegacyAesKey || !hasLegacyBiometricState;
    }

    static boolean shouldClearRecoveredStateOnCipherUse(
            boolean usesIsolatedAlias,
            boolean keyWasCreated
    ) {
        return usesIsolatedAlias && keyWasCreated;
    }
}
