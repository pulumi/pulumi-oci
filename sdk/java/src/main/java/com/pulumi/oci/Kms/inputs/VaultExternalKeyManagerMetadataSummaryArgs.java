// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Kms.inputs.VaultExternalKeyManagerMetadataSummaryOauthMetadataSummaryArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VaultExternalKeyManagerMetadataSummaryArgs extends com.pulumi.resources.ResourceArgs {

    public static final VaultExternalKeyManagerMetadataSummaryArgs Empty = new VaultExternalKeyManagerMetadataSummaryArgs();

    /**
     * URI of the vault on external key manager.
     * 
     */
    @Import(name="externalVaultEndpointUrl")
    private @Nullable Output<String> externalVaultEndpointUrl;

    /**
     * @return URI of the vault on external key manager.
     * 
     */
    public Optional<Output<String>> externalVaultEndpointUrl() {
        return Optional.ofNullable(this.externalVaultEndpointUrl);
    }

    /**
     * Summary about authorization to be returned to the customer as a response.
     * 
     */
    @Import(name="oauthMetadataSummaries")
    private @Nullable Output<List<VaultExternalKeyManagerMetadataSummaryOauthMetadataSummaryArgs>> oauthMetadataSummaries;

    /**
     * @return Summary about authorization to be returned to the customer as a response.
     * 
     */
    public Optional<Output<List<VaultExternalKeyManagerMetadataSummaryOauthMetadataSummaryArgs>>> oauthMetadataSummaries() {
        return Optional.ofNullable(this.oauthMetadataSummaries);
    }

    /**
     * OCID of private endpoint created by customer.
     * 
     */
    @Import(name="privateEndpointId")
    private @Nullable Output<String> privateEndpointId;

    /**
     * @return OCID of private endpoint created by customer.
     * 
     */
    public Optional<Output<String>> privateEndpointId() {
        return Optional.ofNullable(this.privateEndpointId);
    }

    /**
     * Vendor of the external key manager.
     * 
     */
    @Import(name="vendor")
    private @Nullable Output<String> vendor;

    /**
     * @return Vendor of the external key manager.
     * 
     */
    public Optional<Output<String>> vendor() {
        return Optional.ofNullable(this.vendor);
    }

    private VaultExternalKeyManagerMetadataSummaryArgs() {}

    private VaultExternalKeyManagerMetadataSummaryArgs(VaultExternalKeyManagerMetadataSummaryArgs $) {
        this.externalVaultEndpointUrl = $.externalVaultEndpointUrl;
        this.oauthMetadataSummaries = $.oauthMetadataSummaries;
        this.privateEndpointId = $.privateEndpointId;
        this.vendor = $.vendor;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VaultExternalKeyManagerMetadataSummaryArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VaultExternalKeyManagerMetadataSummaryArgs $;

        public Builder() {
            $ = new VaultExternalKeyManagerMetadataSummaryArgs();
        }

        public Builder(VaultExternalKeyManagerMetadataSummaryArgs defaults) {
            $ = new VaultExternalKeyManagerMetadataSummaryArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param externalVaultEndpointUrl URI of the vault on external key manager.
         * 
         * @return builder
         * 
         */
        public Builder externalVaultEndpointUrl(@Nullable Output<String> externalVaultEndpointUrl) {
            $.externalVaultEndpointUrl = externalVaultEndpointUrl;
            return this;
        }

        /**
         * @param externalVaultEndpointUrl URI of the vault on external key manager.
         * 
         * @return builder
         * 
         */
        public Builder externalVaultEndpointUrl(String externalVaultEndpointUrl) {
            return externalVaultEndpointUrl(Output.of(externalVaultEndpointUrl));
        }

        /**
         * @param oauthMetadataSummaries Summary about authorization to be returned to the customer as a response.
         * 
         * @return builder
         * 
         */
        public Builder oauthMetadataSummaries(@Nullable Output<List<VaultExternalKeyManagerMetadataSummaryOauthMetadataSummaryArgs>> oauthMetadataSummaries) {
            $.oauthMetadataSummaries = oauthMetadataSummaries;
            return this;
        }

        /**
         * @param oauthMetadataSummaries Summary about authorization to be returned to the customer as a response.
         * 
         * @return builder
         * 
         */
        public Builder oauthMetadataSummaries(List<VaultExternalKeyManagerMetadataSummaryOauthMetadataSummaryArgs> oauthMetadataSummaries) {
            return oauthMetadataSummaries(Output.of(oauthMetadataSummaries));
        }

        /**
         * @param oauthMetadataSummaries Summary about authorization to be returned to the customer as a response.
         * 
         * @return builder
         * 
         */
        public Builder oauthMetadataSummaries(VaultExternalKeyManagerMetadataSummaryOauthMetadataSummaryArgs... oauthMetadataSummaries) {
            return oauthMetadataSummaries(List.of(oauthMetadataSummaries));
        }

        /**
         * @param privateEndpointId OCID of private endpoint created by customer.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointId(@Nullable Output<String> privateEndpointId) {
            $.privateEndpointId = privateEndpointId;
            return this;
        }

        /**
         * @param privateEndpointId OCID of private endpoint created by customer.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointId(String privateEndpointId) {
            return privateEndpointId(Output.of(privateEndpointId));
        }

        /**
         * @param vendor Vendor of the external key manager.
         * 
         * @return builder
         * 
         */
        public Builder vendor(@Nullable Output<String> vendor) {
            $.vendor = vendor;
            return this;
        }

        /**
         * @param vendor Vendor of the external key manager.
         * 
         * @return builder
         * 
         */
        public Builder vendor(String vendor) {
            return vendor(Output.of(vendor));
        }

        public VaultExternalKeyManagerMetadataSummaryArgs build() {
            return $;
        }
    }

}