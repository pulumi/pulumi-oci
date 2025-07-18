// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.inputs.GetDbmulticloudOracleDbAzureBlobContainersFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDbmulticloudOracleDbAzureBlobContainersPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbmulticloudOracleDbAzureBlobContainersPlainArgs Empty = new GetDbmulticloudOracleDbAzureBlobContainersPlainArgs();

    /**
     * A filter to return Azure Blob Containers.
     * 
     */
    @Import(name="azureStorageAccountName")
    private @Nullable String azureStorageAccountName;

    /**
     * @return A filter to return Azure Blob Containers.
     * 
     */
    public Optional<String> azureStorageAccountName() {
        return Optional.ofNullable(this.azureStorageAccountName);
    }

    /**
     * A filter to return Azure Blob containers.
     * 
     */
    @Import(name="azureStorageContainerName")
    private @Nullable String azureStorageContainerName;

    /**
     * @return A filter to return Azure Blob containers.
     * 
     */
    public Optional<String> azureStorageContainerName() {
        return Optional.ofNullable(this.azureStorageContainerName);
    }

    /**
     * The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return Azure Containers.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return Azure Containers.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetDbmulticloudOracleDbAzureBlobContainersFilter> filters;

    public Optional<List<GetDbmulticloudOracleDbAzureBlobContainersFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return Oracle DB Azure Blob Mount Resources.
     * 
     */
    @Import(name="oracleDbAzureBlobContainerId")
    private @Nullable String oracleDbAzureBlobContainerId;

    /**
     * @return A filter to return Oracle DB Azure Blob Mount Resources.
     * 
     */
    public Optional<String> oracleDbAzureBlobContainerId() {
        return Optional.ofNullable(this.oracleDbAzureBlobContainerId);
    }

    /**
     * A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetDbmulticloudOracleDbAzureBlobContainersPlainArgs() {}

    private GetDbmulticloudOracleDbAzureBlobContainersPlainArgs(GetDbmulticloudOracleDbAzureBlobContainersPlainArgs $) {
        this.azureStorageAccountName = $.azureStorageAccountName;
        this.azureStorageContainerName = $.azureStorageContainerName;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.oracleDbAzureBlobContainerId = $.oracleDbAzureBlobContainerId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbmulticloudOracleDbAzureBlobContainersPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbmulticloudOracleDbAzureBlobContainersPlainArgs $;

        public Builder() {
            $ = new GetDbmulticloudOracleDbAzureBlobContainersPlainArgs();
        }

        public Builder(GetDbmulticloudOracleDbAzureBlobContainersPlainArgs defaults) {
            $ = new GetDbmulticloudOracleDbAzureBlobContainersPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param azureStorageAccountName A filter to return Azure Blob Containers.
         * 
         * @return builder
         * 
         */
        public Builder azureStorageAccountName(@Nullable String azureStorageAccountName) {
            $.azureStorageAccountName = azureStorageAccountName;
            return this;
        }

        /**
         * @param azureStorageContainerName A filter to return Azure Blob containers.
         * 
         * @return builder
         * 
         */
        public Builder azureStorageContainerName(@Nullable String azureStorageContainerName) {
            $.azureStorageContainerName = azureStorageContainerName;
            return this;
        }

        /**
         * @param compartmentId The [ID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return Azure Containers.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetDbmulticloudOracleDbAzureBlobContainersFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDbmulticloudOracleDbAzureBlobContainersFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param oracleDbAzureBlobContainerId A filter to return Oracle DB Azure Blob Mount Resources.
         * 
         * @return builder
         * 
         */
        public Builder oracleDbAzureBlobContainerId(@Nullable String oracleDbAzureBlobContainerId) {
            $.oracleDbAzureBlobContainerId = oracleDbAzureBlobContainerId;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetDbmulticloudOracleDbAzureBlobContainersPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDbmulticloudOracleDbAzureBlobContainersPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
