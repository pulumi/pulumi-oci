// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudMigrations.inputs.GetMigrationPlansFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMigrationPlansPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMigrationPlansPlainArgs Empty = new GetMigrationPlansPlainArgs();

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
    private @Nullable List<GetMigrationPlansFilter> filters;

    public Optional<List<GetMigrationPlansFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique migration identifier
     * 
     */
    @Import(name="migrationId")
    private @Nullable String migrationId;

    /**
     * @return Unique migration identifier
     * 
     */
    public Optional<String> migrationId() {
        return Optional.ofNullable(this.migrationId);
    }

    /**
     * Unique migration plan identifier
     * 
     */
    @Import(name="migrationPlanId")
    private @Nullable String migrationPlanId;

    /**
     * @return Unique migration plan identifier
     * 
     */
    public Optional<String> migrationPlanId() {
        return Optional.ofNullable(this.migrationPlanId);
    }

    /**
     * The current state of the migration plan.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current state of the migration plan.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetMigrationPlansPlainArgs() {}

    private GetMigrationPlansPlainArgs(GetMigrationPlansPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.migrationId = $.migrationId;
        this.migrationPlanId = $.migrationPlanId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMigrationPlansPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMigrationPlansPlainArgs $;

        public Builder() {
            $ = new GetMigrationPlansPlainArgs();
        }

        public Builder(GetMigrationPlansPlainArgs defaults) {
            $ = new GetMigrationPlansPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetMigrationPlansFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMigrationPlansFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param migrationId Unique migration identifier
         * 
         * @return builder
         * 
         */
        public Builder migrationId(@Nullable String migrationId) {
            $.migrationId = migrationId;
            return this;
        }

        /**
         * @param migrationPlanId Unique migration plan identifier
         * 
         * @return builder
         * 
         */
        public Builder migrationPlanId(@Nullable String migrationPlanId) {
            $.migrationPlanId = migrationPlanId;
            return this;
        }

        /**
         * @param state The current state of the migration plan.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetMigrationPlansPlainArgs build() {
            return $;
        }
    }

}