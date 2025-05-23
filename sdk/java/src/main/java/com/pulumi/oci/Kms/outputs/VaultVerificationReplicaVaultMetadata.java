// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class VaultVerificationReplicaVaultMetadata {
    private String idcsAccountNameUrl;
    private String privateEndpointId;
    private String vaultType;

    private VaultVerificationReplicaVaultMetadata() {}
    public String idcsAccountNameUrl() {
        return this.idcsAccountNameUrl;
    }
    public String privateEndpointId() {
        return this.privateEndpointId;
    }
    public String vaultType() {
        return this.vaultType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VaultVerificationReplicaVaultMetadata defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String idcsAccountNameUrl;
        private String privateEndpointId;
        private String vaultType;
        public Builder() {}
        public Builder(VaultVerificationReplicaVaultMetadata defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.idcsAccountNameUrl = defaults.idcsAccountNameUrl;
    	      this.privateEndpointId = defaults.privateEndpointId;
    	      this.vaultType = defaults.vaultType;
        }

        @CustomType.Setter
        public Builder idcsAccountNameUrl(String idcsAccountNameUrl) {
            if (idcsAccountNameUrl == null) {
              throw new MissingRequiredPropertyException("VaultVerificationReplicaVaultMetadata", "idcsAccountNameUrl");
            }
            this.idcsAccountNameUrl = idcsAccountNameUrl;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointId(String privateEndpointId) {
            if (privateEndpointId == null) {
              throw new MissingRequiredPropertyException("VaultVerificationReplicaVaultMetadata", "privateEndpointId");
            }
            this.privateEndpointId = privateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder vaultType(String vaultType) {
            if (vaultType == null) {
              throw new MissingRequiredPropertyException("VaultVerificationReplicaVaultMetadata", "vaultType");
            }
            this.vaultType = vaultType;
            return this;
        }
        public VaultVerificationReplicaVaultMetadata build() {
            final var _resultValue = new VaultVerificationReplicaVaultMetadata();
            _resultValue.idcsAccountNameUrl = idcsAccountNameUrl;
            _resultValue.privateEndpointId = privateEndpointId;
            _resultValue.vaultType = vaultType;
            return _resultValue;
        }
    }
}
