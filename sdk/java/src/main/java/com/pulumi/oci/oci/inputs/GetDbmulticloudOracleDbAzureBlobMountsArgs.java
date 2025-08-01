// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.inputs.GetDbmulticloudOracleDbAzureBlobMountsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDbmulticloudOracleDbAzureBlobMountsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbmulticloudOracleDbAzureBlobMountsArgs Empty = new GetDbmulticloudOracleDbAzureBlobMountsArgs();

    /**
     * The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return Oracle DB Azure Blob Mount Resources.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return Oracle DB Azure Blob Mount Resources.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDbmulticloudOracleDbAzureBlobMountsFilterArgs>> filters;

    public Optional<Output<List<GetDbmulticloudOracleDbAzureBlobMountsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return Oracle DB Azure Blob Mount Resources.
     * 
     */
    @Import(name="oracleDbAzureBlobContainerId")
    private @Nullable Output<String> oracleDbAzureBlobContainerId;

    /**
     * @return A filter to return Oracle DB Azure Blob Mount Resources.
     * 
     */
    public Optional<Output<String>> oracleDbAzureBlobContainerId() {
        return Optional.ofNullable(this.oracleDbAzureBlobContainerId);
    }

    /**
     * ID of Oracle DB Azure Blob Mount Resource.
     * 
     */
    @Import(name="oracleDbAzureBlobMountId")
    private @Nullable Output<String> oracleDbAzureBlobMountId;

    /**
     * @return ID of Oracle DB Azure Blob Mount Resource.
     * 
     */
    public Optional<Output<String>> oracleDbAzureBlobMountId() {
        return Optional.ofNullable(this.oracleDbAzureBlobMountId);
    }

    /**
     * A filter to return Oracle DB Azure Blob Mount Resources.
     * 
     */
    @Import(name="oracleDbAzureConnectorId")
    private @Nullable Output<String> oracleDbAzureConnectorId;

    /**
     * @return A filter to return Oracle DB Azure Blob Mount Resources.
     * 
     */
    public Optional<Output<String>> oracleDbAzureConnectorId() {
        return Optional.ofNullable(this.oracleDbAzureConnectorId);
    }

    /**
     * A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetDbmulticloudOracleDbAzureBlobMountsArgs() {}

    private GetDbmulticloudOracleDbAzureBlobMountsArgs(GetDbmulticloudOracleDbAzureBlobMountsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.oracleDbAzureBlobContainerId = $.oracleDbAzureBlobContainerId;
        this.oracleDbAzureBlobMountId = $.oracleDbAzureBlobMountId;
        this.oracleDbAzureConnectorId = $.oracleDbAzureConnectorId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbmulticloudOracleDbAzureBlobMountsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbmulticloudOracleDbAzureBlobMountsArgs $;

        public Builder() {
            $ = new GetDbmulticloudOracleDbAzureBlobMountsArgs();
        }

        public Builder(GetDbmulticloudOracleDbAzureBlobMountsArgs defaults) {
            $ = new GetDbmulticloudOracleDbAzureBlobMountsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return Oracle DB Azure Blob Mount Resources.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return Oracle DB Azure Blob Mount Resources.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetDbmulticloudOracleDbAzureBlobMountsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDbmulticloudOracleDbAzureBlobMountsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDbmulticloudOracleDbAzureBlobMountsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param oracleDbAzureBlobContainerId A filter to return Oracle DB Azure Blob Mount Resources.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureBlobContainerId(@Nullable Output<String> oracleDbAzureBlobContainerId) {
            $.oracleDbAzureBlobContainerId = oracleDbAzureBlobContainerId;
            return this;
        }

        /**
         * @param oracleDbAzureBlobContainerId A filter to return Oracle DB Azure Blob Mount Resources.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureBlobContainerId(String oracleDbAzureBlobContainerId) {
            return oracleDbAzureBlobContainerId(Output.of(oracleDbAzureBlobContainerId));
        }

        /**
         * @param oracleDbAzureBlobMountId ID of Oracle DB Azure Blob Mount Resource.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureBlobMountId(@Nullable Output<String> oracleDbAzureBlobMountId) {
            $.oracleDbAzureBlobMountId = oracleDbAzureBlobMountId;
            return this;
        }

        /**
         * @param oracleDbAzureBlobMountId ID of Oracle DB Azure Blob Mount Resource.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureBlobMountId(String oracleDbAzureBlobMountId) {
            return oracleDbAzureBlobMountId(Output.of(oracleDbAzureBlobMountId));
        }

        /**
         * @param oracleDbAzureConnectorId A filter to return Oracle DB Azure Blob Mount Resources.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureConnectorId(@Nullable Output<String> oracleDbAzureConnectorId) {
            $.oracleDbAzureConnectorId = oracleDbAzureConnectorId;
            return this;
        }

        /**
         * @param oracleDbAzureConnectorId A filter to return Oracle DB Azure Blob Mount Resources.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureConnectorId(String oracleDbAzureConnectorId) {
            return oracleDbAzureConnectorId(Output.of(oracleDbAzureConnectorId));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetDbmulticloudOracleDbAzureBlobMountsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobMountsArgs", "compartmentId");
            }
            return $;
        }
    }

}
