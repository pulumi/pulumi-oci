// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAutonomousDatabaseInstanceWalletManagementArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousDatabaseInstanceWalletManagementArgs Empty = new GetAutonomousDatabaseInstanceWalletManagementArgs();

    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="autonomousDatabaseId", required=true)
    private Output<String> autonomousDatabaseId;

    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> autonomousDatabaseId() {
        return this.autonomousDatabaseId;
    }

    private GetAutonomousDatabaseInstanceWalletManagementArgs() {}

    private GetAutonomousDatabaseInstanceWalletManagementArgs(GetAutonomousDatabaseInstanceWalletManagementArgs $) {
        this.autonomousDatabaseId = $.autonomousDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousDatabaseInstanceWalletManagementArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousDatabaseInstanceWalletManagementArgs $;

        public Builder() {
            $ = new GetAutonomousDatabaseInstanceWalletManagementArgs();
        }

        public Builder(GetAutonomousDatabaseInstanceWalletManagementArgs defaults) {
            $ = new GetAutonomousDatabaseInstanceWalletManagementArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousDatabaseId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(Output<String> autonomousDatabaseId) {
            $.autonomousDatabaseId = autonomousDatabaseId;
            return this;
        }

        /**
         * @param autonomousDatabaseId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            return autonomousDatabaseId(Output.of(autonomousDatabaseId));
        }

        public GetAutonomousDatabaseInstanceWalletManagementArgs build() {
            if ($.autonomousDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetAutonomousDatabaseInstanceWalletManagementArgs", "autonomousDatabaseId");
            }
            return $;
        }
    }

}
