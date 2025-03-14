// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class KeyExternalKeyReferenceDetail {
    /**
     * @return ExternalKeyId refers to the globally unique key Id associated with the key created in external vault in CTM.
     * 
     */
    private @Nullable String externalKeyId;
    /**
     * @return Key version ID associated with the external key.
     * 
     */
    private @Nullable String externalKeyVersionId;

    private KeyExternalKeyReferenceDetail() {}
    /**
     * @return ExternalKeyId refers to the globally unique key Id associated with the key created in external vault in CTM.
     * 
     */
    public Optional<String> externalKeyId() {
        return Optional.ofNullable(this.externalKeyId);
    }
    /**
     * @return Key version ID associated with the external key.
     * 
     */
    public Optional<String> externalKeyVersionId() {
        return Optional.ofNullable(this.externalKeyVersionId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(KeyExternalKeyReferenceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String externalKeyId;
        private @Nullable String externalKeyVersionId;
        public Builder() {}
        public Builder(KeyExternalKeyReferenceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.externalKeyId = defaults.externalKeyId;
    	      this.externalKeyVersionId = defaults.externalKeyVersionId;
        }

        @CustomType.Setter
        public Builder externalKeyId(@Nullable String externalKeyId) {

            this.externalKeyId = externalKeyId;
            return this;
        }
        @CustomType.Setter
        public Builder externalKeyVersionId(@Nullable String externalKeyVersionId) {

            this.externalKeyVersionId = externalKeyVersionId;
            return this;
        }
        public KeyExternalKeyReferenceDetail build() {
            final var _resultValue = new KeyExternalKeyReferenceDetail();
            _resultValue.externalKeyId = externalKeyId;
            _resultValue.externalKeyVersionId = externalKeyVersionId;
            return _resultValue;
        }
    }
}
