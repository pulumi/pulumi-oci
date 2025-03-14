// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SignState extends com.pulumi.resources.ResourceArgs {

    public static final SignState Empty = new SignState();

    /**
     * The service endpoint to perform cryptographic operations against. Cryptographic operations include &#39;Encrypt,&#39; &#39;Decrypt,&#39;, &#39;GenerateDataEncryptionKey&#39;, &#39;Sign&#39; and &#39;Verify&#39; operations. see Vault Crypto endpoint.
     * 
     */
    @Import(name="cryptoEndpoint")
    private @Nullable Output<String> cryptoEndpoint;

    /**
     * @return The service endpoint to perform cryptographic operations against. Cryptographic operations include &#39;Encrypt,&#39; &#39;Decrypt,&#39;, &#39;GenerateDataEncryptionKey&#39;, &#39;Sign&#39; and &#39;Verify&#39; operations. see Vault Crypto endpoint.
     * 
     */
    public Optional<Output<String>> cryptoEndpoint() {
        return Optional.ofNullable(this.cryptoEndpoint);
    }

    /**
     * The OCID of the key used to sign the message.
     * 
     */
    @Import(name="keyId")
    private @Nullable Output<String> keyId;

    /**
     * @return The OCID of the key used to sign the message.
     * 
     */
    public Optional<Output<String>> keyId() {
        return Optional.ofNullable(this.keyId);
    }

    /**
     * The OCID of the key version used to sign the message.
     * 
     */
    @Import(name="keyVersionId")
    private @Nullable Output<String> keyVersionId;

    /**
     * @return The OCID of the key version used to sign the message.
     * 
     */
    public Optional<Output<String>> keyVersionId() {
        return Optional.ofNullable(this.keyVersionId);
    }

    /**
     * The base64-encoded binary data object denoting the message or message digest to sign. You can have a message up to 4096 bytes in size. To sign a larger message, provide the message digest.
     * 
     */
    @Import(name="message")
    private @Nullable Output<String> message;

    /**
     * @return The base64-encoded binary data object denoting the message or message digest to sign. You can have a message up to 4096 bytes in size. To sign a larger message, provide the message digest.
     * 
     */
    public Optional<Output<String>> message() {
        return Optional.ofNullable(this.message);
    }

    /**
     * Denotes whether the value of the message parameter is a raw message or a message digest. The default value, `RAW`, indicates a message. To indicate a message digest, use `DIGEST`.
     * 
     */
    @Import(name="messageType")
    private @Nullable Output<String> messageType;

    /**
     * @return Denotes whether the value of the message parameter is a raw message or a message digest. The default value, `RAW`, indicates a message. To indicate a message digest, use `DIGEST`.
     * 
     */
    public Optional<Output<String>> messageType() {
        return Optional.ofNullable(this.messageType);
    }

    /**
     * The base64-encoded binary data object denoting the cryptographic signature generated for the message or message digest.
     * 
     */
    @Import(name="signature")
    private @Nullable Output<String> signature;

    /**
     * @return The base64-encoded binary data object denoting the cryptographic signature generated for the message or message digest.
     * 
     */
    public Optional<Output<String>> signature() {
        return Optional.ofNullable(this.signature);
    }

    /**
     * The algorithm to use to sign the message or message digest. For RSA keys, supported signature schemes include PKCS #1 and RSASSA-PSS, along with different hashing algorithms. For ECDSA keys, ECDSA is the supported signature scheme with different hashing algorithms. When you pass a message digest for signing, ensure that you specify the same hashing algorithm as used when creating the message digest.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="signingAlgorithm")
    private @Nullable Output<String> signingAlgorithm;

    /**
     * @return The algorithm to use to sign the message or message digest. For RSA keys, supported signature schemes include PKCS #1 and RSASSA-PSS, along with different hashing algorithms. For ECDSA keys, ECDSA is the supported signature scheme with different hashing algorithms. When you pass a message digest for signing, ensure that you specify the same hashing algorithm as used when creating the message digest.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> signingAlgorithm() {
        return Optional.ofNullable(this.signingAlgorithm);
    }

    private SignState() {}

    private SignState(SignState $) {
        this.cryptoEndpoint = $.cryptoEndpoint;
        this.keyId = $.keyId;
        this.keyVersionId = $.keyVersionId;
        this.message = $.message;
        this.messageType = $.messageType;
        this.signature = $.signature;
        this.signingAlgorithm = $.signingAlgorithm;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SignState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SignState $;

        public Builder() {
            $ = new SignState();
        }

        public Builder(SignState defaults) {
            $ = new SignState(Objects.requireNonNull(defaults));
        }

        /**
         * @param cryptoEndpoint The service endpoint to perform cryptographic operations against. Cryptographic operations include &#39;Encrypt,&#39; &#39;Decrypt,&#39;, &#39;GenerateDataEncryptionKey&#39;, &#39;Sign&#39; and &#39;Verify&#39; operations. see Vault Crypto endpoint.
         * 
         * @return builder
         * 
         */
        public Builder cryptoEndpoint(@Nullable Output<String> cryptoEndpoint) {
            $.cryptoEndpoint = cryptoEndpoint;
            return this;
        }

        /**
         * @param cryptoEndpoint The service endpoint to perform cryptographic operations against. Cryptographic operations include &#39;Encrypt,&#39; &#39;Decrypt,&#39;, &#39;GenerateDataEncryptionKey&#39;, &#39;Sign&#39; and &#39;Verify&#39; operations. see Vault Crypto endpoint.
         * 
         * @return builder
         * 
         */
        public Builder cryptoEndpoint(String cryptoEndpoint) {
            return cryptoEndpoint(Output.of(cryptoEndpoint));
        }

        /**
         * @param keyId The OCID of the key used to sign the message.
         * 
         * @return builder
         * 
         */
        public Builder keyId(@Nullable Output<String> keyId) {
            $.keyId = keyId;
            return this;
        }

        /**
         * @param keyId The OCID of the key used to sign the message.
         * 
         * @return builder
         * 
         */
        public Builder keyId(String keyId) {
            return keyId(Output.of(keyId));
        }

        /**
         * @param keyVersionId The OCID of the key version used to sign the message.
         * 
         * @return builder
         * 
         */
        public Builder keyVersionId(@Nullable Output<String> keyVersionId) {
            $.keyVersionId = keyVersionId;
            return this;
        }

        /**
         * @param keyVersionId The OCID of the key version used to sign the message.
         * 
         * @return builder
         * 
         */
        public Builder keyVersionId(String keyVersionId) {
            return keyVersionId(Output.of(keyVersionId));
        }

        /**
         * @param message The base64-encoded binary data object denoting the message or message digest to sign. You can have a message up to 4096 bytes in size. To sign a larger message, provide the message digest.
         * 
         * @return builder
         * 
         */
        public Builder message(@Nullable Output<String> message) {
            $.message = message;
            return this;
        }

        /**
         * @param message The base64-encoded binary data object denoting the message or message digest to sign. You can have a message up to 4096 bytes in size. To sign a larger message, provide the message digest.
         * 
         * @return builder
         * 
         */
        public Builder message(String message) {
            return message(Output.of(message));
        }

        /**
         * @param messageType Denotes whether the value of the message parameter is a raw message or a message digest. The default value, `RAW`, indicates a message. To indicate a message digest, use `DIGEST`.
         * 
         * @return builder
         * 
         */
        public Builder messageType(@Nullable Output<String> messageType) {
            $.messageType = messageType;
            return this;
        }

        /**
         * @param messageType Denotes whether the value of the message parameter is a raw message or a message digest. The default value, `RAW`, indicates a message. To indicate a message digest, use `DIGEST`.
         * 
         * @return builder
         * 
         */
        public Builder messageType(String messageType) {
            return messageType(Output.of(messageType));
        }

        /**
         * @param signature The base64-encoded binary data object denoting the cryptographic signature generated for the message or message digest.
         * 
         * @return builder
         * 
         */
        public Builder signature(@Nullable Output<String> signature) {
            $.signature = signature;
            return this;
        }

        /**
         * @param signature The base64-encoded binary data object denoting the cryptographic signature generated for the message or message digest.
         * 
         * @return builder
         * 
         */
        public Builder signature(String signature) {
            return signature(Output.of(signature));
        }

        /**
         * @param signingAlgorithm The algorithm to use to sign the message or message digest. For RSA keys, supported signature schemes include PKCS #1 and RSASSA-PSS, along with different hashing algorithms. For ECDSA keys, ECDSA is the supported signature scheme with different hashing algorithms. When you pass a message digest for signing, ensure that you specify the same hashing algorithm as used when creating the message digest.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder signingAlgorithm(@Nullable Output<String> signingAlgorithm) {
            $.signingAlgorithm = signingAlgorithm;
            return this;
        }

        /**
         * @param signingAlgorithm The algorithm to use to sign the message or message digest. For RSA keys, supported signature schemes include PKCS #1 and RSASSA-PSS, along with different hashing algorithms. For ECDSA keys, ECDSA is the supported signature scheme with different hashing algorithms. When you pass a message digest for signing, ensure that you specify the same hashing algorithm as used when creating the message digest.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder signingAlgorithm(String signingAlgorithm) {
            return signingAlgorithm(Output.of(signingAlgorithm));
        }

        public SignState build() {
            return $;
        }
    }

}
