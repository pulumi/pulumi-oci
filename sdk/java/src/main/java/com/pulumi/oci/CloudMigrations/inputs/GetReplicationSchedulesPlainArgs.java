// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.GetReplicationSchedulesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetReplicationSchedulesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetReplicationSchedulesPlainArgs Empty = new GetReplicationSchedulesPlainArgs();

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
     * A filter to return only resources that match the entire given display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire given display name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetReplicationSchedulesFilter> filters;

    public Optional<List<GetReplicationSchedulesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique replication schedule identifier in query
     * 
     */
    @Import(name="replicationScheduleId")
    private @Nullable String replicationScheduleId;

    /**
     * @return Unique replication schedule identifier in query
     * 
     */
    public Optional<String> replicationScheduleId() {
        return Optional.ofNullable(this.replicationScheduleId);
    }

    /**
     * The current state of the replication schedule.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current state of the replication schedule.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetReplicationSchedulesPlainArgs() {}

    private GetReplicationSchedulesPlainArgs(GetReplicationSchedulesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.replicationScheduleId = $.replicationScheduleId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetReplicationSchedulesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetReplicationSchedulesPlainArgs $;

        public Builder() {
            $ = new GetReplicationSchedulesPlainArgs();
        }

        public Builder(GetReplicationSchedulesPlainArgs defaults) {
            $ = new GetReplicationSchedulesPlainArgs(Objects.requireNonNull(defaults));
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
         * @param displayName A filter to return only resources that match the entire given display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetReplicationSchedulesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetReplicationSchedulesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param replicationScheduleId Unique replication schedule identifier in query
         * 
         * @return builder
         * 
         */
        public Builder replicationScheduleId(@Nullable String replicationScheduleId) {
            $.replicationScheduleId = replicationScheduleId;
            return this;
        }

        /**
         * @param state The current state of the replication schedule.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetReplicationSchedulesPlainArgs build() {
            return $;
        }
    }

}
