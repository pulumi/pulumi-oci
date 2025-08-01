// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FleetAppsManagement.inputs.GetMaintenanceWindowsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMaintenanceWindowsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMaintenanceWindowsPlainArgs Empty = new GetMaintenanceWindowsPlainArgs();

    /**
     * The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
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
    private @Nullable List<GetMaintenanceWindowsFilter> filters;

    public Optional<List<GetMaintenanceWindowsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique identifier or OCID for listing a single maintenance window by id. Either compartmentId or id must be provided.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return Unique identifier or OCID for listing a single maintenance window by id. Either compartmentId or id must be provided.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources whose lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources whose lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only resources whose timeScheduleStart is greater than or equal to the provided date and time.
     * 
     */
    @Import(name="timeScheduleStartGreaterThanOrEqualTo")
    private @Nullable String timeScheduleStartGreaterThanOrEqualTo;

    /**
     * @return A filter to return only resources whose timeScheduleStart is greater than or equal to the provided date and time.
     * 
     */
    public Optional<String> timeScheduleStartGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeScheduleStartGreaterThanOrEqualTo);
    }

    private GetMaintenanceWindowsPlainArgs() {}

    private GetMaintenanceWindowsPlainArgs(GetMaintenanceWindowsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.state = $.state;
        this.timeScheduleStartGreaterThanOrEqualTo = $.timeScheduleStartGreaterThanOrEqualTo;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMaintenanceWindowsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMaintenanceWindowsPlainArgs $;

        public Builder() {
            $ = new GetMaintenanceWindowsPlainArgs();
        }

        public Builder(GetMaintenanceWindowsPlainArgs defaults) {
            $ = new GetMaintenanceWindowsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
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

        public Builder filters(@Nullable List<GetMaintenanceWindowsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMaintenanceWindowsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique identifier or OCID for listing a single maintenance window by id. Either compartmentId or id must be provided.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param state A filter to return only resources whose lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param timeScheduleStartGreaterThanOrEqualTo A filter to return only resources whose timeScheduleStart is greater than or equal to the provided date and time.
         * 
         * @return builder
         * 
         */
        public Builder timeScheduleStartGreaterThanOrEqualTo(@Nullable String timeScheduleStartGreaterThanOrEqualTo) {
            $.timeScheduleStartGreaterThanOrEqualTo = timeScheduleStartGreaterThanOrEqualTo;
            return this;
        }

        public GetMaintenanceWindowsPlainArgs build() {
            return $;
        }
    }

}
