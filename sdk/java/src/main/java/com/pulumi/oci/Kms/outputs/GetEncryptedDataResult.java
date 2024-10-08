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
public final class GetEncryptedDataResult {
    private @Nullable Map<String,String> associatedData;
    /**
     * @return The encrypted data.
     * 
     */
    private String ciphertext;
    private String cryptoEndpoint;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String keyId;
    private String plaintext;

    private GetEncryptedDataResult() {}
    public Map<String,String> associatedData() {
        return this.associatedData == null ? Map.of() : this.associatedData;
    }
    /**
     * @return The encrypted data.
     * 
     */
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
    public String plaintext() {
        return this.plaintext;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEncryptedDataResult defaults) {
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
        public Builder() {}
        public Builder(GetEncryptedDataResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.associatedData = defaults.associatedData;
    	      this.ciphertext = defaults.ciphertext;
    	      this.cryptoEndpoint = defaults.cryptoEndpoint;
    	      this.id = defaults.id;
    	      this.keyId = defaults.keyId;
    	      this.plaintext = defaults.plaintext;
        }

        @CustomType.Setter
        public Builder associatedData(@Nullable Map<String,String> associatedData) {

            this.associatedData = associatedData;
            return this;
        }
        @CustomType.Setter
        public Builder ciphertext(String ciphertext) {
            if (ciphertext == null) {
              throw new MissingRequiredPropertyException("GetEncryptedDataResult", "ciphertext");
            }
            this.ciphertext = ciphertext;
            return this;
        }
        @CustomType.Setter
        public Builder cryptoEndpoint(String cryptoEndpoint) {
            if (cryptoEndpoint == null) {
              throw new MissingRequiredPropertyException("GetEncryptedDataResult", "cryptoEndpoint");
            }
            this.cryptoEndpoint = cryptoEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetEncryptedDataResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder keyId(String keyId) {
            if (keyId == null) {
              throw new MissingRequiredPropertyException("GetEncryptedDataResult", "keyId");
            }
            this.keyId = keyId;
            return this;
        }
        @CustomType.Setter
        public Builder plaintext(String plaintext) {
            if (plaintext == null) {
              throw new MissingRequiredPropertyException("GetEncryptedDataResult", "plaintext");
            }
            this.plaintext = plaintext;
            return this;
        }
        public GetEncryptedDataResult build() {
            final var _resultValue = new GetEncryptedDataResult();
            _resultValue.associatedData = associatedData;
            _resultValue.ciphertext = ciphertext;
            _resultValue.cryptoEndpoint = cryptoEndpoint;
            _resultValue.id = id;
            _resultValue.keyId = keyId;
            _resultValue.plaintext = plaintext;
            return _resultValue;
        }
    }
}
