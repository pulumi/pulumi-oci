// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetStreamPackagingConfigsStreamPackagingConfigCollectionItemEncryption {
    /**
     * @return The encryption algorithm for the stream packaging configuration.
     * 
     */
    private String algorithm;
    /**
     * @return The identifier of the customer managed Vault KMS symmetric encryption key (null if Oracle managed).
     * 
     */
    private String kmsKeyId;

    private GetStreamPackagingConfigsStreamPackagingConfigCollectionItemEncryption() {}
    /**
     * @return The encryption algorithm for the stream packaging configuration.
     * 
     */
    public String algorithm() {
        return this.algorithm;
    }
    /**
     * @return The identifier of the customer managed Vault KMS symmetric encryption key (null if Oracle managed).
     * 
     */
    public String kmsKeyId() {
        return this.kmsKeyId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetStreamPackagingConfigsStreamPackagingConfigCollectionItemEncryption defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String algorithm;
        private String kmsKeyId;
        public Builder() {}
        public Builder(GetStreamPackagingConfigsStreamPackagingConfigCollectionItemEncryption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.algorithm = defaults.algorithm;
    	      this.kmsKeyId = defaults.kmsKeyId;
        }

        @CustomType.Setter
        public Builder algorithm(String algorithm) {
            this.algorithm = Objects.requireNonNull(algorithm);
            return this;
        }
        @CustomType.Setter
        public Builder kmsKeyId(String kmsKeyId) {
            this.kmsKeyId = Objects.requireNonNull(kmsKeyId);
            return this;
        }
        public GetStreamPackagingConfigsStreamPackagingConfigCollectionItemEncryption build() {
            final var o = new GetStreamPackagingConfigsStreamPackagingConfigCollectionItemEncryption();
            o.algorithm = algorithm;
            o.kmsKeyId = kmsKeyId;
            return o;
        }
    }
}