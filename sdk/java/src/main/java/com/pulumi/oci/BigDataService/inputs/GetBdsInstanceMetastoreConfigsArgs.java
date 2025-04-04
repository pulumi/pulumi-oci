// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.inputs.GetBdsInstanceMetastoreConfigsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBdsInstanceMetastoreConfigsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBdsInstanceMetastoreConfigsArgs Empty = new GetBdsInstanceMetastoreConfigsArgs();

    /**
     * The ID of the API key that is associated with the external metastore in the metastore configuration
     * 
     */
    @Import(name="bdsApiKeyId")
    private @Nullable Output<String> bdsApiKeyId;

    /**
     * @return The ID of the API key that is associated with the external metastore in the metastore configuration
     * 
     */
    public Optional<Output<String>> bdsApiKeyId() {
        return Optional.ofNullable(this.bdsApiKeyId);
    }

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetBdsInstanceMetastoreConfigsFilterArgs>> filters;

    public Optional<Output<List<GetBdsInstanceMetastoreConfigsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the Data Catalog metastore in the metastore configuration
     * 
     */
    @Import(name="metastoreId")
    private @Nullable Output<String> metastoreId;

    /**
     * @return The OCID of the Data Catalog metastore in the metastore configuration
     * 
     */
    public Optional<Output<String>> metastoreId() {
        return Optional.ofNullable(this.metastoreId);
    }

    /**
     * The type of the metastore in the metastore configuration
     * 
     */
    @Import(name="metastoreType")
    private @Nullable Output<String> metastoreType;

    /**
     * @return The type of the metastore in the metastore configuration
     * 
     */
    public Optional<Output<String>> metastoreType() {
        return Optional.ofNullable(this.metastoreType);
    }

    /**
     * The lifecycle state of the metastore in the metastore configuration
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The lifecycle state of the metastore in the metastore configuration
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetBdsInstanceMetastoreConfigsArgs() {}

    private GetBdsInstanceMetastoreConfigsArgs(GetBdsInstanceMetastoreConfigsArgs $) {
        this.bdsApiKeyId = $.bdsApiKeyId;
        this.bdsInstanceId = $.bdsInstanceId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.metastoreId = $.metastoreId;
        this.metastoreType = $.metastoreType;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBdsInstanceMetastoreConfigsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBdsInstanceMetastoreConfigsArgs $;

        public Builder() {
            $ = new GetBdsInstanceMetastoreConfigsArgs();
        }

        public Builder(GetBdsInstanceMetastoreConfigsArgs defaults) {
            $ = new GetBdsInstanceMetastoreConfigsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsApiKeyId The ID of the API key that is associated with the external metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder bdsApiKeyId(@Nullable Output<String> bdsApiKeyId) {
            $.bdsApiKeyId = bdsApiKeyId;
            return this;
        }

        /**
         * @param bdsApiKeyId The ID of the API key that is associated with the external metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder bdsApiKeyId(String bdsApiKeyId) {
            return bdsApiKeyId(Output.of(bdsApiKeyId));
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(Output<String> bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            return bdsInstanceId(Output.of(bdsInstanceId));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetBdsInstanceMetastoreConfigsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetBdsInstanceMetastoreConfigsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetBdsInstanceMetastoreConfigsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param metastoreId The OCID of the Data Catalog metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder metastoreId(@Nullable Output<String> metastoreId) {
            $.metastoreId = metastoreId;
            return this;
        }

        /**
         * @param metastoreId The OCID of the Data Catalog metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder metastoreId(String metastoreId) {
            return metastoreId(Output.of(metastoreId));
        }

        /**
         * @param metastoreType The type of the metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder metastoreType(@Nullable Output<String> metastoreType) {
            $.metastoreType = metastoreType;
            return this;
        }

        /**
         * @param metastoreType The type of the metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder metastoreType(String metastoreType) {
            return metastoreType(Output.of(metastoreType));
        }

        /**
         * @param state The lifecycle state of the metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The lifecycle state of the metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetBdsInstanceMetastoreConfigsArgs build() {
            if ($.bdsInstanceId == null) {
                throw new MissingRequiredPropertyException("GetBdsInstanceMetastoreConfigsArgs", "bdsInstanceId");
            }
            return $;
        }
    }

}
