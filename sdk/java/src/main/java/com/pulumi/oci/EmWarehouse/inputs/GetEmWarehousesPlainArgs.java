// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.EmWarehouse.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.EmWarehouse.inputs.GetEmWarehousesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetEmWarehousesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEmWarehousesPlainArgs Empty = new GetEmWarehousesPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
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
    private @Nullable List<GetEmWarehousesFilter> filters;

    public Optional<List<GetEmWarehousesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * unique EmWarehouse identifier
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return unique EmWarehouse identifier
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * unique operationsInsightsWarehouseId identifier
     * 
     */
    @Import(name="operationsInsightsWarehouseId")
    private @Nullable String operationsInsightsWarehouseId;

    /**
     * @return unique operationsInsightsWarehouseId identifier
     * 
     */
    public Optional<String> operationsInsightsWarehouseId() {
        return Optional.ofNullable(this.operationsInsightsWarehouseId);
    }

    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetEmWarehousesPlainArgs() {}

    private GetEmWarehousesPlainArgs(GetEmWarehousesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.operationsInsightsWarehouseId = $.operationsInsightsWarehouseId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEmWarehousesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEmWarehousesPlainArgs $;

        public Builder() {
            $ = new GetEmWarehousesPlainArgs();
        }

        public Builder(GetEmWarehousesPlainArgs defaults) {
            $ = new GetEmWarehousesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
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

        public Builder filters(@Nullable List<GetEmWarehousesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetEmWarehousesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id unique EmWarehouse identifier
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param operationsInsightsWarehouseId unique operationsInsightsWarehouseId identifier
         * 
         * @return builder
         * 
         */
        public Builder operationsInsightsWarehouseId(@Nullable String operationsInsightsWarehouseId) {
            $.operationsInsightsWarehouseId = operationsInsightsWarehouseId;
            return this;
        }

        /**
         * @param state A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetEmWarehousesPlainArgs build() {
            return $;
        }
    }

}