// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Opsi.inputs.GetOperationsInsightsWarehouseUsersFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetOperationsInsightsWarehouseUsersPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOperationsInsightsWarehouseUsersPlainArgs Empty = new GetOperationsInsightsWarehouseUsersPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A filter to return only resources that match the entire display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetOperationsInsightsWarehouseUsersFilter> filters;

    public Optional<List<GetOperationsInsightsWarehouseUsersFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique Operations Insights Warehouse User identifier
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return Unique Operations Insights Warehouse User identifier
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * Unique Operations Insights Warehouse identifier
     * 
     */
    @Import(name="operationsInsightsWarehouseId", required=true)
    private String operationsInsightsWarehouseId;

    /**
     * @return Unique Operations Insights Warehouse identifier
     * 
     */
    public String operationsInsightsWarehouseId() {
        return this.operationsInsightsWarehouseId;
    }

    /**
     * Lifecycle states
     * 
     */
    @Import(name="states")
    private @Nullable List<String> states;

    /**
     * @return Lifecycle states
     * 
     */
    public Optional<List<String>> states() {
        return Optional.ofNullable(this.states);
    }

    private GetOperationsInsightsWarehouseUsersPlainArgs() {}

    private GetOperationsInsightsWarehouseUsersPlainArgs(GetOperationsInsightsWarehouseUsersPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.operationsInsightsWarehouseId = $.operationsInsightsWarehouseId;
        this.states = $.states;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOperationsInsightsWarehouseUsersPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOperationsInsightsWarehouseUsersPlainArgs $;

        public Builder() {
            $ = new GetOperationsInsightsWarehouseUsersPlainArgs();
        }

        public Builder(GetOperationsInsightsWarehouseUsersPlainArgs defaults) {
            $ = new GetOperationsInsightsWarehouseUsersPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetOperationsInsightsWarehouseUsersFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetOperationsInsightsWarehouseUsersFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique Operations Insights Warehouse User identifier
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param operationsInsightsWarehouseId Unique Operations Insights Warehouse identifier
         * 
         * @return builder
         * 
         */
        public Builder operationsInsightsWarehouseId(String operationsInsightsWarehouseId) {
            $.operationsInsightsWarehouseId = operationsInsightsWarehouseId;
            return this;
        }

        /**
         * @param states Lifecycle states
         * 
         * @return builder
         * 
         */
        public Builder states(@Nullable List<String> states) {
            $.states = states;
            return this;
        }

        /**
         * @param states Lifecycle states
         * 
         * @return builder
         * 
         */
        public Builder states(String... states) {
            return states(List.of(states));
        }

        public GetOperationsInsightsWarehouseUsersPlainArgs build() {
            $.operationsInsightsWarehouseId = Objects.requireNonNull($.operationsInsightsWarehouseId, "expected parameter 'operationsInsightsWarehouseId' to be non-null");
            return $;
        }
    }

}