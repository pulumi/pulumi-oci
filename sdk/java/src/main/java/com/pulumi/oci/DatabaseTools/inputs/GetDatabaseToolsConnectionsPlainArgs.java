// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseTools.inputs.GetDatabaseToolsConnectionsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDatabaseToolsConnectionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDatabaseToolsConnectionsPlainArgs Empty = new GetDatabaseToolsConnectionsPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire specified display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire specified display name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetDatabaseToolsConnectionsFilter> filters;

    public Optional<List<GetDatabaseToolsConnectionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources their `lifecycleState` matches the specified `lifecycleState`.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources their `lifecycleState` matches the specified `lifecycleState`.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only resources their type matches the specified type.
     * 
     */
    @Import(name="types")
    private @Nullable List<String> types;

    /**
     * @return A filter to return only resources their type matches the specified type.
     * 
     */
    public Optional<List<String>> types() {
        return Optional.ofNullable(this.types);
    }

    private GetDatabaseToolsConnectionsPlainArgs() {}

    private GetDatabaseToolsConnectionsPlainArgs(GetDatabaseToolsConnectionsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
        this.types = $.types;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDatabaseToolsConnectionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDatabaseToolsConnectionsPlainArgs $;

        public Builder() {
            $ = new GetDatabaseToolsConnectionsPlainArgs();
        }

        public Builder(GetDatabaseToolsConnectionsPlainArgs defaults) {
            $ = new GetDatabaseToolsConnectionsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire specified display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetDatabaseToolsConnectionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDatabaseToolsConnectionsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only resources their `lifecycleState` matches the specified `lifecycleState`.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param types A filter to return only resources their type matches the specified type.
         * 
         * @return builder
         * 
         */
        public Builder types(@Nullable List<String> types) {
            $.types = types;
            return this;
        }

        /**
         * @param types A filter to return only resources their type matches the specified type.
         * 
         * @return builder
         * 
         */
        public Builder types(String... types) {
            return types(List.of(types));
        }

        public GetDatabaseToolsConnectionsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}