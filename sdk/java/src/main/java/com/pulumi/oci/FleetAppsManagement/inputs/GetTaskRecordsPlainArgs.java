// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FleetAppsManagement.inputs.GetTaskRecordsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetTaskRecordsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTaskRecordsPlainArgs Empty = new GetTaskRecordsPlainArgs();

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
    private @Nullable List<GetTaskRecordsFilter> filters;

    public Optional<List<GetTaskRecordsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique identifier or OCID for listing a single task record by id. Either compartmentId or id must be provided.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return Unique identifier or OCID for listing a single task record by id. Either compartmentId or id must be provided.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return task records whose operation matches the given lifecycle operation.
     * 
     */
    @Import(name="operation")
    private @Nullable String operation;

    /**
     * @return A filter to return task records whose operation matches the given lifecycle operation.
     * 
     */
    public Optional<String> operation() {
        return Optional.ofNullable(this.operation);
    }

    /**
     * The platform for the task record.
     * 
     */
    @Import(name="platform")
    private @Nullable String platform;

    /**
     * @return The platform for the task record.
     * 
     */
    public Optional<String> platform() {
        return Optional.ofNullable(this.platform);
    }

    /**
     * The current state of the task record.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current state of the task record.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The type of the Task.
     * 
     */
    @Import(name="type")
    private @Nullable String type;

    /**
     * @return The type of the Task.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    private GetTaskRecordsPlainArgs() {}

    private GetTaskRecordsPlainArgs(GetTaskRecordsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.operation = $.operation;
        this.platform = $.platform;
        this.state = $.state;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTaskRecordsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTaskRecordsPlainArgs $;

        public Builder() {
            $ = new GetTaskRecordsPlainArgs();
        }

        public Builder(GetTaskRecordsPlainArgs defaults) {
            $ = new GetTaskRecordsPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetTaskRecordsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetTaskRecordsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique identifier or OCID for listing a single task record by id. Either compartmentId or id must be provided.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param operation A filter to return task records whose operation matches the given lifecycle operation.
         * 
         * @return builder
         * 
         */
        public Builder operation(@Nullable String operation) {
            $.operation = operation;
            return this;
        }

        /**
         * @param platform The platform for the task record.
         * 
         * @return builder
         * 
         */
        public Builder platform(@Nullable String platform) {
            $.platform = platform;
            return this;
        }

        /**
         * @param state The current state of the task record.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param type The type of the Task.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable String type) {
            $.type = type;
            return this;
        }

        public GetTaskRecordsPlainArgs build() {
            return $;
        }
    }

}
