package com.oblador.keychain.cipherStorage;

import java.nio.charset.StandardCharsets;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.oblador.keychain.KeychainModule;
import com.oblador.keychain.KeychainModule.KnownCiphers;
import com.oblador.keychain.SecurityLevel;
import com.oblador.keychain.ErrorHelper;
import com.oblador.keychain.exceptions.CryptoFailedException;
import com.oblador.keychain.exceptions.KeyStoreAccessException;

import androidx.biometric.BiometricPrompt;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.KeySpec;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;

import java.io.ByteArrayInputStream;

/**
 * @see <a href="https://proandroiddev.com/secure-data-in-android-initialization-vector-6ca1c659762c">Secure Data in Android</a>
 * @see <a href="https://stackoverflow.com/questions/36827352/android-aes-with-keystore-produces-different-cipher-text-with-same-plain-text">AES cipher</a>
 */
@TargetApi(Build.VERSION_CODES.M)
@SuppressWarnings({"unused", "WeakerAccess"})
public class CipherStorageKeystoreAesCbc extends CipherStorageBase {
  //region Constants
  /** AES */
  public static final String ALGORITHM_AES = KeyProperties.KEY_ALGORITHM_AES;
  /** CBC */
  public static final String BLOCK_MODE_CBC = KeyProperties.BLOCK_MODE_CBC;
  /** PKCS7 */
  public static final String PADDING_PKCS7 = KeyProperties.ENCRYPTION_PADDING_PKCS7;
  /** Transformation path. */
  public static final String ENCRYPTION_TRANSFORMATION =
    ALGORITHM_AES + "/" + BLOCK_MODE_CBC + "/" + PADDING_PKCS7;
  /** Key size. */
  public static final int ENCRYPTION_KEY_SIZE = 256;

  public static final String DEFAULT_SERVICE = "RN_KEYCHAIN_DEFAULT_ALIAS";
  //endregion

  //region Configuration
  @Override
  public String getCipherStorageName() {
    return KnownCiphers.AES;
  }

  /** API23 is a requirement. */
  @Override
  public int getMinSupportedApiLevel() {
    return Build.VERSION_CODES.M;
  }

  /** it can guarantee security levels up to SECURE_HARDWARE/SE/StrongBox */
  @Override
  public SecurityLevel securityLevel() {
    return SecurityLevel.SECURE_HARDWARE;
  }

  /** Biometry is Not Supported. */
  @Override
  public boolean isBiometrySupported() {
    return true;
  }

  /** AES. */
  @Override
  @NonNull
  protected String getEncryptionAlgorithm() {
    return ALGORITHM_AES;
  }

  /** AES/CBC/PKCS7Padding */
  @NonNull
  @Override
  protected String getEncryptionTransformation() {
    return ENCRYPTION_TRANSFORMATION;
  }

  /** {@inheritDoc}. Override for saving the compatibility with previous version of lib. */
  @Override
  public String getDefaultAliasServiceName() {
    return DEFAULT_SERVICE;
  }

  //endregion

  //region Overrides
  @Override
  @NonNull
  public EncryptionResult encrypt(@NonNull final String alias,
                                  @NonNull final String username,
                                  @NonNull final String password,
                                  @NonNull final SecurityLevel level)
    throws CryptoFailedException {

    throwIfInsufficientLevel(level);

    final String safeAlias = getDefaultAliasIfEmpty(alias, getDefaultAliasServiceName());
    final AtomicInteger retries = new AtomicInteger(1);

    Key key = null;
    try {
      key = extractGeneratedKey(safeAlias, level, retries);

      return new EncryptionResult(
        encryptString(key, username),
        encryptString(key, password),
        this);
    } catch (GeneralSecurityException e) {
      // @SuppressWarnings("ConstantConditions") final DecryptionContext context =
      //   new DecryptionContext(safeAlias, key, password, username);

      // handler.askAccessPermissions(context);
      throw new CryptoFailedException("Could not encrypt data with alias: " + alias, e);
    } catch (Throwable fail) {
      throw new CryptoFailedException("Unknown error with alias: " + alias +
        ", error: " + fail.getMessage(), fail);
    }
  }

  @Override
  public EncryptionResult encrypt(@NonNull final DecryptionResultHandler handler,
                                  @NonNull final String alias,
                                  @NonNull final String username,
                                  @NonNull final String password,
                                  @NonNull final SecurityLevel level)
    throws CryptoFailedException {
      throwIfInsufficientLevel(level);

      final String safeAlias = getDefaultAliasIfEmpty(alias, getDefaultAliasServiceName());
      final AtomicInteger retries = new AtomicInteger(1);

      Key key = null;
      try {

        key = extractGeneratedKey(safeAlias, level, retries);

        if (KeychainModule.isSecuredByBiometry(alias)) {
          @SuppressWarnings("ConstantConditions") final EncryptionContext context =
            new EncryptionContext(safeAlias, key, password, username);

          handler.askAccessPermissions(context);
          if (handler.getError() != null) {
            ErrorHelper.handleHandlerError(handler.getError().getMessage());
          }
          return handler.getEncryptionResult();
        } else {
          return new EncryptionResult(
            username.getBytes(),
            encryptString(key, password),
            this);
        }
        // throw new CryptoFailedException("Could not encrypt data with alias: " + alias, e);
      } catch (Throwable fail) {
        throw new CryptoFailedException("Unknown error with alias: " + alias +
          ", error: " + fail.getMessage(), fail);
      }
    }

  @Override
  @NonNull
  public DecryptionResult decrypt(
                                  @NonNull final String alias,
                                  @NonNull final byte[] username,
                                  @NonNull final byte[] password,
                                  @NonNull final SecurityLevel level)
    throws CryptoFailedException {

    throwIfInsufficientLevel(level);

    final String safeAlias = getDefaultAliasIfEmpty(alias, getDefaultAliasServiceName());
    final AtomicInteger retries = new AtomicInteger(1);

    try {
      final Key key = extractGeneratedKey(safeAlias, level, retries);
      return new DecryptionResult(
        new String(username, StandardCharsets.UTF_8),
        decryptBytes(key, password),
        getSecurityLevel(key));
    } catch (GeneralSecurityException e) {
      throw new CryptoFailedException("Could not decrypt data with alias: " + alias, e);
    } catch (Throwable fail) {
      throw new CryptoFailedException("Unknown error with alias: " + alias +
        ", error: " + fail.getMessage(), fail);
    }
  }

  /** Redirect call to {@link #decrypt(String, byte[], byte[], SecurityLevel)} method. */
  @Override
  public void decrypt(@NonNull final DecryptionResultHandler handler,
                      @NonNull final String service,
                      @NonNull final byte[] username,
                      @NonNull final byte[] password,
                      @NonNull final SecurityLevel level) throws CryptoFailedException {
    throwIfInsufficientLevel(level);

    final String safeAlias = getDefaultAliasIfEmpty(service, getDefaultAliasServiceName());
    final AtomicInteger retries = new AtomicInteger(1);
    boolean shouldAskPermissions = false;

    Key key = null;

    try {
      // key is always NOT NULL otherwise GeneralSecurityException raised
      // key = extractGeneratedKey(safeAlias, level, retries);

      try {
      if (KeychainModule.isSecuredByBiometry(service)) {
        throw new GeneralSecurityException("BIOMETRICS");
      } else {
        final DecryptionResult results = decrypt(service, username, password, level);
        handler.onDecrypt(results, null);
       }
      } catch(GeneralSecurityException e) {
        // key is always NOT NULL otherwise GeneralSecurityException raised
        key = extractGeneratedKey(safeAlias, level, retries);
        // expected that KEY instance is extracted and we caught exception on decryptBytes operation
        @SuppressWarnings("ConstantConditions") final DecryptionContext context =
        new DecryptionContext(safeAlias, key, password, username);
        handler.askAccessPermissions(context);
      }
    } catch (final Exception ex) {
      Log.d(LOG_TAG, "Unlock of keystore is needed. Error: " + ex.getMessage(), ex);

      // expected that KEY instance is extracted and we caught exception on decryptBytes operation
      @SuppressWarnings("ConstantConditions") final DecryptionContext context =
        new DecryptionContext(safeAlias, key, username, password);

      handler.askAccessPermissions(context);
    } catch (final Throwable fail) {
      // any other exception treated as a failure
      handler.onDecrypt(null, fail);
    }
  }
  //endregion

  //region Implementation

  /** Get encryption algorithm specification builder instance. */
  @NonNull
  @Override
  protected KeyGenParameterSpec.Builder getKeyGenSpecBuilder(@NonNull final String alias)
    throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    final int purposes = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;

    if (KeychainModule.isSecuredByBiometry(alias)) {
      return new KeyGenParameterSpec.Builder(alias, purposes)
        .setBlockModes(BLOCK_MODE_CBC)
        .setEncryptionPaddings(PADDING_PKCS7)
        .setUserAuthenticationRequired(true)
        .setInvalidatedByBiometricEnrollment(true)
        .setRandomizedEncryptionRequired(true)
        .setKeySize(ENCRYPTION_KEY_SIZE);
    } else {
      return new KeyGenParameterSpec.Builder(alias, purposes)
        .setBlockModes(BLOCK_MODE_CBC)
        .setEncryptionPaddings(PADDING_PKCS7)
        .setRandomizedEncryptionRequired(true)
        .setKeySize(ENCRYPTION_KEY_SIZE);
    }

  }

  /** Get information about provided key. */
  @NonNull
  @Override
  protected KeyInfo getKeyInfo(@NonNull final Key key) throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    final SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE_TYPE);
    final KeySpec keySpec = factory.getKeySpec((SecretKey) key, KeyInfo.class);

    return (KeyInfo) keySpec;
  }

  /** Try to generate key from provided specification. */
  @NonNull
  @Override
  protected Key generateKey(@NonNull final KeyGenParameterSpec spec) throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    KeyGenerator generator = KeyGenerator.getInstance(getEncryptionAlgorithm(), KEYSTORE_TYPE);
    generator.init(spec);

    return generator.generateKey();
  }

  //endregion

  //region Initialization Vector encrypt/decrypt support
  @NonNull
  @Override
  public byte[] encryptString(@NonNull final Key key, @NonNull final String value)
    throws GeneralSecurityException, CryptoFailedException, IOException {
    return encryptString(key, value, null, IV.encrypt);
  }

  @NonNull
  @Override
  public byte[] encryptString(@NonNull final Key key, @NonNull final String value, @NonNull final Cipher cipher)
    throws GeneralSecurityException, CryptoFailedException, IOException {
    return encryptString(key, value, cipher, IV.encryptWithoutInit);
  }

  @NonNull
  @Override
  public String decryptBytes(@NonNull final Key key, @NonNull final byte[] bytes)
    throws GeneralSecurityException, IOException {
    return decryptBytes(key, bytes, null, IV.decrypt);
  }

  @NonNull
  @Override
  public String decryptBytes(@NonNull final Key key, @NonNull final byte[] bytes, @NonNull final Cipher cipher)
    throws GeneralSecurityException, IOException {
    return decryptBytes(key, bytes, cipher, IV.decryptWithoutInit);
  }
  //endregion
}
