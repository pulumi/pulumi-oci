// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Kms.outputs.VaultExternalKeyManagerMetadataOauthMetadata;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class VaultExternalKeyManagerMetadata {
    /**
     * @return URI of the vault on external key manager.
     * 
     */
    private String externalVaultEndpointUrl;
    /**
     * @return Authorization details required to get access token from IDP for accessing protected resources.
     * 
     */
    private VaultExternalKeyManagerMetadataOauthMetadata oauthMetadata;
    /**
     * @return OCID of private endpoint created by customer.
     * 
     */
    private String privateEndpointId;

    private VaultExternalKeyManagerMetadata() {}
    /**
     * @return URI of the vault on external key manager.
     * 
     */
    public String externalVaultEndpointUrl() {
        return this.externalVaultEndpointUrl;
    }
    /**
     * @return Authorization details required to get access token from IDP for accessing protected resources.
     * 
     */
    public VaultExternalKeyManagerMetadataOauthMetadata oauthMetadata() {
        return this.oauthMetadata;
    }
    /**
     * @return OCID of private endpoint created by customer.
     * 
     */
    public String privateEndpointId() {
        return this.privateEndpointId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VaultExternalKeyManagerMetadata defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String externalVaultEndpointUrl;
        private VaultExternalKeyManagerMetadataOauthMetadata oauthMetadata;
        private String privateEndpointId;
        public Builder() {}
        public Builder(VaultExternalKeyManagerMetadata defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.externalVaultEndpointUrl = defaults.externalVaultEndpointUrl;
    	      this.oauthMetadata = defaults.oauthMetadata;
    	      this.privateEndpointId = defaults.privateEndpointId;
        }

        @CustomType.Setter
        public Builder externalVaultEndpointUrl(String externalVaultEndpointUrl) {
            if (externalVaultEndpointUrl == null) {
              throw new MissingRequiredPropertyException("VaultExternalKeyManagerMetadata", "externalVaultEndpointUrl");
            }
            this.externalVaultEndpointUrl = externalVaultEndpointUrl;
            return this;
        }
        @CustomType.Setter
        public Builder oauthMetadata(VaultExternalKeyManagerMetadataOauthMetadata oauthMetadata) {
            if (oauthMetadata == null) {
              throw new MissingRequiredPropertyException("VaultExternalKeyManagerMetadata", "oauthMetadata");
            }
            this.oauthMetadata = oauthMetadata;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointId(String privateEndpointId) {
            if (privateEndpointId == null) {
              throw new MissingRequiredPropertyException("VaultExternalKeyManagerMetadata", "privateEndpointId");
            }
            this.privateEndpointId = privateEndpointId;
            return this;
        }
        public VaultExternalKeyManagerMetadata build() {
            final var _resultValue = new VaultExternalKeyManagerMetadata();
            _resultValue.externalVaultEndpointUrl = externalVaultEndpointUrl;
            _resultValue.oauthMetadata = oauthMetadata;
            _resultValue.privateEndpointId = privateEndpointId;
            return _resultValue;
        }
    }
}
