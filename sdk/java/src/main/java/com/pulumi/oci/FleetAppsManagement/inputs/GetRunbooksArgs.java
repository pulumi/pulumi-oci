// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FleetAppsManagement.inputs.GetRunbooksFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRunbooksArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRunbooksArgs Empty = new GetRunbooksArgs();

    /**
     * The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
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
    private @Nullable Output<List<GetRunbooksFilterArgs>> filters;

    public Optional<Output<List<GetRunbooksFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique identifier or OCID for listing a single Runbook by id. Either compartmentId or id must be provided.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return Unique identifier or OCID for listing a single Runbook by id. Either compartmentId or id must be provided.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return runbooks whose operation matches the given lifecycle operation.
     * 
     */
    @Import(name="operation")
    private @Nullable Output<String> operation;

    /**
     * @return A filter to return runbooks whose operation matches the given lifecycle operation.
     * 
     */
    public Optional<Output<String>> operation() {
        return Optional.ofNullable(this.operation);
    }

    /**
     * A filter to return runbooks whose platform matches the given platform.
     * 
     */
    @Import(name="platform")
    private @Nullable Output<String> platform;

    /**
     * @return A filter to return runbooks whose platform matches the given platform.
     * 
     */
    public Optional<Output<String>> platform() {
        return Optional.ofNullable(this.platform);
    }

    /**
     * A filter to return only resources whose lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources whose lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return runbooks whose type matches the given type.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return A filter to return runbooks whose type matches the given type.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private GetRunbooksArgs() {}

    private GetRunbooksArgs(GetRunbooksArgs $) {
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
    public static Builder builder(GetRunbooksArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRunbooksArgs $;

        public Builder() {
            $ = new GetRunbooksArgs();
        }

        public Builder(GetRunbooksArgs defaults) {
            $ = new GetRunbooksArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
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

        public Builder filters(@Nullable Output<List<GetRunbooksFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetRunbooksFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetRunbooksFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique identifier or OCID for listing a single Runbook by id. Either compartmentId or id must be provided.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id Unique identifier or OCID for listing a single Runbook by id. Either compartmentId or id must be provided.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param operation A filter to return runbooks whose operation matches the given lifecycle operation.
         * 
         * @return builder
         * 
         */
        public Builder operation(@Nullable Output<String> operation) {
            $.operation = operation;
            return this;
        }

        /**
         * @param operation A filter to return runbooks whose operation matches the given lifecycle operation.
         * 
         * @return builder
         * 
         */
        public Builder operation(String operation) {
            return operation(Output.of(operation));
        }

        /**
         * @param platform A filter to return runbooks whose platform matches the given platform.
         * 
         * @return builder
         * 
         */
        public Builder platform(@Nullable Output<String> platform) {
            $.platform = platform;
            return this;
        }

        /**
         * @param platform A filter to return runbooks whose platform matches the given platform.
         * 
         * @return builder
         * 
         */
        public Builder platform(String platform) {
            return platform(Output.of(platform));
        }

        /**
         * @param state A filter to return only resources whose lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources whose lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param type A filter to return runbooks whose type matches the given type.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type A filter to return runbooks whose type matches the given type.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public GetRunbooksArgs build() {
            return $;
        }
    }

}
