// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetDecryptedDataResult {
    private @Nullable Map<String,String> associatedData;
    private String ciphertext;
    private String cryptoEndpoint;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String keyId;
    /**
     * @return The decrypted data, in the form of a base64-encoded value.
     * 
     */
    private String plaintext;
    /**
     * @return Checksum of the decrypted data.
     * 
     */
    private String plaintextChecksum;

    private GetDecryptedDataResult() {}
    public Map<String,String> associatedData() {
        return this.associatedData == null ? Map.of() : this.associatedData;
    }
    public String ciphertext() {
        return this.ciphertext;
    }
    public String cryptoEndpoint() {
        return this.cryptoEndpoint;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String keyId() {
        return this.keyId;
    }
    /**
     * @return The decrypted data, in the form of a base64-encoded value.
     * 
     */
    public String plaintext() {
        return this.plaintext;
    }
    /**
     * @return Checksum of the decrypted data.
     * 
     */
    public String plaintextChecksum() {
        return this.plaintextChecksum;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDecryptedDataResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Map<String,String> associatedData;
        private String ciphertext;
        private String cryptoEndpoint;
        private String id;
        private String keyId;
        private String plaintext;
        private String plaintextChecksum;
        public Builder() {}
        public Builder(GetDecryptedDataResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.associatedData = defaults.associatedData;
    	      this.ciphertext = defaults.ciphertext;
    	      this.cryptoEndpoint = defaults.cryptoEndpoint;
    	      this.id = defaults.id;
    	      this.keyId = defaults.keyId;
    	      this.plaintext = defaults.plaintext;
    	      this.plaintextChecksum = defaults.plaintextChecksum;
        }

        @CustomType.Setter
        public Builder associatedData(@Nullable Map<String,String> associatedData) {

            this.associatedData = associatedData;
            return this;
        }
        @CustomType.Setter
        public Builder ciphertext(String ciphertext) {
            if (ciphertext == null) {
              throw new MissingRequiredPropertyException("GetDecryptedDataResult", "ciphertext");
            }
            this.ciphertext = ciphertext;
            return this;
        }
        @CustomType.Setter
        public Builder cryptoEndpoint(String cryptoEndpoint) {
            if (cryptoEndpoint == null) {
              throw new MissingRequiredPropertyException("GetDecryptedDataResult", "cryptoEndpoint");
            }
            this.cryptoEndpoint = cryptoEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDecryptedDataResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder keyId(String keyId) {
            if (keyId == null) {
              throw new MissingRequiredPropertyException("GetDecryptedDataResult", "keyId");
            }
            this.keyId = keyId;
            return this;
        }
        @CustomType.Setter
        public Builder plaintext(String plaintext) {
            if (plaintext == null) {
              throw new MissingRequiredPropertyException("GetDecryptedDataResult", "plaintext");
            }
            this.plaintext = plaintext;
            return this;
        }
        @CustomType.Setter
        public Builder plaintextChecksum(String plaintextChecksum) {
            if (plaintextChecksum == null) {
              throw new MissingRequiredPropertyException("GetDecryptedDataResult", "plaintextChecksum");
            }
            this.plaintextChecksum = plaintextChecksum;
            return this;
        }
        public GetDecryptedDataResult build() {
            final var _resultValue = new GetDecryptedDataResult();
            _resultValue.associatedData = associatedData;
            _resultValue.ciphertext = ciphertext;
            _resultValue.cryptoEndpoint = cryptoEndpoint;
            _resultValue.id = id;
            _resultValue.keyId = keyId;
            _resultValue.plaintext = plaintext;
            _resultValue.plaintextChecksum = plaintextChecksum;
            return _resultValue;
        }
    }
}
