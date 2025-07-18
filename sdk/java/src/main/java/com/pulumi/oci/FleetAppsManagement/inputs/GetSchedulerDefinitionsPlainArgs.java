// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FleetAppsManagement.inputs.GetSchedulerDefinitionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSchedulerDefinitionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSchedulerDefinitionsPlainArgs Empty = new GetSchedulerDefinitionsPlainArgs();

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
    private @Nullable List<GetSchedulerDefinitionsFilter> filters;

    public Optional<List<GetSchedulerDefinitionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * unique Fleet identifier
     * 
     */
    @Import(name="fleetId")
    private @Nullable String fleetId;

    /**
     * @return unique Fleet identifier
     * 
     */
    public Optional<String> fleetId() {
        return Optional.ofNullable(this.fleetId);
    }

    /**
     * Unique identifier or OCID for listing a single Schedule Definition by id. Either compartmentId or id must be provided.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return Unique identifier or OCID for listing a single Schedule Definition by id. Either compartmentId or id must be provided.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only schedule definitions whose associated maintenanceWindowId matches the given maintenanceWindowId.
     * 
     */
    @Import(name="maintenanceWindowId")
    private @Nullable String maintenanceWindowId;

    /**
     * @return A filter to return only schedule definitions whose associated maintenanceWindowId matches the given maintenanceWindowId.
     * 
     */
    public Optional<String> maintenanceWindowId() {
        return Optional.ofNullable(this.maintenanceWindowId);
    }

    /**
     * A filter to return only dchedule definitions whose assocaited product matches the given product
     * 
     */
    @Import(name="product")
    private @Nullable String product;

    /**
     * @return A filter to return only dchedule definitions whose assocaited product matches the given product
     * 
     */
    public Optional<String> product() {
        return Optional.ofNullable(this.product);
    }

    /**
     * A filter to return only schedule definitions whose associated runbookId matches the given runbookId.
     * 
     */
    @Import(name="runbookId")
    private @Nullable String runbookId;

    /**
     * @return A filter to return only schedule definitions whose associated runbookId matches the given runbookId.
     * 
     */
    public Optional<String> runbookId() {
        return Optional.ofNullable(this.runbookId);
    }

    /**
     * RunbookVersion Name filter
     * 
     */
    @Import(name="runbookVersionName")
    private @Nullable String runbookVersionName;

    /**
     * @return RunbookVersion Name filter
     * 
     */
    public Optional<String> runbookVersionName() {
        return Optional.ofNullable(this.runbookVersionName);
    }

    /**
     * A filter to return only scheduleDefinitions whose lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only scheduleDefinitions whose lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Scheduled Time
     * 
     */
    @Import(name="timeScheduledGreaterThanOrEqualTo")
    private @Nullable String timeScheduledGreaterThanOrEqualTo;

    /**
     * @return Scheduled Time
     * 
     */
    public Optional<String> timeScheduledGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeScheduledGreaterThanOrEqualTo);
    }

    /**
     * Scheduled Time
     * 
     */
    @Import(name="timeScheduledLessThan")
    private @Nullable String timeScheduledLessThan;

    /**
     * @return Scheduled Time
     * 
     */
    public Optional<String> timeScheduledLessThan() {
        return Optional.ofNullable(this.timeScheduledLessThan);
    }

    private GetSchedulerDefinitionsPlainArgs() {}

    private GetSchedulerDefinitionsPlainArgs(GetSchedulerDefinitionsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.fleetId = $.fleetId;
        this.id = $.id;
        this.maintenanceWindowId = $.maintenanceWindowId;
        this.product = $.product;
        this.runbookId = $.runbookId;
        this.runbookVersionName = $.runbookVersionName;
        this.state = $.state;
        this.timeScheduledGreaterThanOrEqualTo = $.timeScheduledGreaterThanOrEqualTo;
        this.timeScheduledLessThan = $.timeScheduledLessThan;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSchedulerDefinitionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSchedulerDefinitionsPlainArgs $;

        public Builder() {
            $ = new GetSchedulerDefinitionsPlainArgs();
        }

        public Builder(GetSchedulerDefinitionsPlainArgs defaults) {
            $ = new GetSchedulerDefinitionsPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetSchedulerDefinitionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetSchedulerDefinitionsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param fleetId unique Fleet identifier
         * 
         * @return builder
         * 
         */
        public Builder fleetId(@Nullable String fleetId) {
            $.fleetId = fleetId;
            return this;
        }

        /**
         * @param id Unique identifier or OCID for listing a single Schedule Definition by id. Either compartmentId or id must be provided.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param maintenanceWindowId A filter to return only schedule definitions whose associated maintenanceWindowId matches the given maintenanceWindowId.
         * 
         * @return builder
         * 
         */
        public Builder maintenanceWindowId(@Nullable String maintenanceWindowId) {
            $.maintenanceWindowId = maintenanceWindowId;
            return this;
        }

        /**
         * @param product A filter to return only dchedule definitions whose assocaited product matches the given product
         * 
         * @return builder
         * 
         */
        public Builder product(@Nullable String product) {
            $.product = product;
            return this;
        }

        /**
         * @param runbookId A filter to return only schedule definitions whose associated runbookId matches the given runbookId.
         * 
         * @return builder
         * 
         */
        public Builder runbookId(@Nullable String runbookId) {
            $.runbookId = runbookId;
            return this;
        }

        /**
         * @param runbookVersionName RunbookVersion Name filter
         * 
         * @return builder
         * 
         */
        public Builder runbookVersionName(@Nullable String runbookVersionName) {
            $.runbookVersionName = runbookVersionName;
            return this;
        }

        /**
         * @param state A filter to return only scheduleDefinitions whose lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param timeScheduledGreaterThanOrEqualTo Scheduled Time
         * 
         * @return builder
         * 
         */
        public Builder timeScheduledGreaterThanOrEqualTo(@Nullable String timeScheduledGreaterThanOrEqualTo) {
            $.timeScheduledGreaterThanOrEqualTo = timeScheduledGreaterThanOrEqualTo;
            return this;
        }

        /**
         * @param timeScheduledLessThan Scheduled Time
         * 
         * @return builder
         * 
         */
        public Builder timeScheduledLessThan(@Nullable String timeScheduledLessThan) {
            $.timeScheduledLessThan = timeScheduledLessThan;
            return this;
        }

        public GetSchedulerDefinitionsPlainArgs build() {
            return $;
        }
    }

}
