package com.oblador.keychain;

import com.oblador.keychain.exceptions.CryptoFailedException;
import androidx.biometric.BiometricPrompt;

public class ErrorHelper {
  public static void handleHandlerError(String errorMessage) throws CryptoFailedException {
    if (errorMessage.contains("code: " + BiometricPrompt.ERROR_NEGATIVE_BUTTON) ||
      errorMessage.contains("code: " + BiometricPrompt.ERROR_USER_CANCELED) ||
      errorMessage.contains("code: " + BiometricPrompt.ERROR_LOCKOUT) ||
      errorMessage.contains("code: " + BiometricPrompt.ERROR_LOCKOUT_PERMANENT) ||
      errorMessage.contains("code: " + BiometricPrompt.ERROR_NO_BIOMETRICS) ||
      errorMessage.contains("javax.crypto.IllegalBlockSizeException")) {
      throw new CryptoFailedException(errorMessage);
    }
  }
}
