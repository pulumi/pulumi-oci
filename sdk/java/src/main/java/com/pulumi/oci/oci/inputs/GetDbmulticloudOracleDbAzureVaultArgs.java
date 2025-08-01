// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDbmulticloudOracleDbAzureVaultArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbmulticloudOracleDbAzureVaultArgs Empty = new GetDbmulticloudOracleDbAzureVaultArgs();

    /**
     * The ID of the Oracle DB Azure Vault Resource.
     * 
     */
    @Import(name="oracleDbAzureVaultId", required=true)
    private Output<String> oracleDbAzureVaultId;

    /**
     * @return The ID of the Oracle DB Azure Vault Resource.
     * 
     */
    public Output<String> oracleDbAzureVaultId() {
        return this.oracleDbAzureVaultId;
    }

    private GetDbmulticloudOracleDbAzureVaultArgs() {}

    private GetDbmulticloudOracleDbAzureVaultArgs(GetDbmulticloudOracleDbAzureVaultArgs $) {
        this.oracleDbAzureVaultId = $.oracleDbAzureVaultId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbmulticloudOracleDbAzureVaultArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbmulticloudOracleDbAzureVaultArgs $;

        public Builder() {
            $ = new GetDbmulticloudOracleDbAzureVaultArgs();
        }

        public Builder(GetDbmulticloudOracleDbAzureVaultArgs defaults) {
            $ = new GetDbmulticloudOracleDbAzureVaultArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param oracleDbAzureVaultId The ID of the Oracle DB Azure Vault Resource.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureVaultId(Output<String> oracleDbAzureVaultId) {
            $.oracleDbAzureVaultId = oracleDbAzureVaultId;
            return this;
        }

        /**
         * @param oracleDbAzureVaultId The ID of the Oracle DB Azure Vault Resource.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureVaultId(String oracleDbAzureVaultId) {
            return oracleDbAzureVaultId(Output.of(oracleDbAzureVaultId));
        }

        public GetDbmulticloudOracleDbAzureVaultArgs build() {
            if ($.oracleDbAzureVaultId == null) {
                throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureVaultArgs", "oracleDbAzureVaultId");
            }
            return $;
        }
    }

}
