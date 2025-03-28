// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.inputs.GetBdsInstanceMetastoreConfigsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBdsInstanceMetastoreConfigsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBdsInstanceMetastoreConfigsPlainArgs Empty = new GetBdsInstanceMetastoreConfigsPlainArgs();

    /**
     * The ID of the API key that is associated with the external metastore in the metastore configuration
     * 
     */
    @Import(name="bdsApiKeyId")
    private @Nullable String bdsApiKeyId;

    /**
     * @return The ID of the API key that is associated with the external metastore in the metastore configuration
     * 
     */
    public Optional<String> bdsApiKeyId() {
        return Optional.ofNullable(this.bdsApiKeyId);
    }

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private String bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public String bdsInstanceId() {
        return this.bdsInstanceId;
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetBdsInstanceMetastoreConfigsFilter> filters;

    public Optional<List<GetBdsInstanceMetastoreConfigsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the Data Catalog metastore in the metastore configuration
     * 
     */
    @Import(name="metastoreId")
    private @Nullable String metastoreId;

    /**
     * @return The OCID of the Data Catalog metastore in the metastore configuration
     * 
     */
    public Optional<String> metastoreId() {
        return Optional.ofNullable(this.metastoreId);
    }

    /**
     * The type of the metastore in the metastore configuration
     * 
     */
    @Import(name="metastoreType")
    private @Nullable String metastoreType;

    /**
     * @return The type of the metastore in the metastore configuration
     * 
     */
    public Optional<String> metastoreType() {
        return Optional.ofNullable(this.metastoreType);
    }

    /**
     * The lifecycle state of the metastore in the metastore configuration
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The lifecycle state of the metastore in the metastore configuration
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetBdsInstanceMetastoreConfigsPlainArgs() {}

    private GetBdsInstanceMetastoreConfigsPlainArgs(GetBdsInstanceMetastoreConfigsPlainArgs $) {
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
    public static Builder builder(GetBdsInstanceMetastoreConfigsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBdsInstanceMetastoreConfigsPlainArgs $;

        public Builder() {
            $ = new GetBdsInstanceMetastoreConfigsPlainArgs();
        }

        public Builder(GetBdsInstanceMetastoreConfigsPlainArgs defaults) {
            $ = new GetBdsInstanceMetastoreConfigsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsApiKeyId The ID of the API key that is associated with the external metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder bdsApiKeyId(@Nullable String bdsApiKeyId) {
            $.bdsApiKeyId = bdsApiKeyId;
            return this;
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetBdsInstanceMetastoreConfigsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetBdsInstanceMetastoreConfigsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param metastoreId The OCID of the Data Catalog metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder metastoreId(@Nullable String metastoreId) {
            $.metastoreId = metastoreId;
            return this;
        }

        /**
         * @param metastoreType The type of the metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder metastoreType(@Nullable String metastoreType) {
            $.metastoreType = metastoreType;
            return this;
        }

        /**
         * @param state The lifecycle state of the metastore in the metastore configuration
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetBdsInstanceMetastoreConfigsPlainArgs build() {
            if ($.bdsInstanceId == null) {
                throw new MissingRequiredPropertyException("GetBdsInstanceMetastoreConfigsPlainArgs", "bdsInstanceId");
            }
            return $;
        }
    }

}
