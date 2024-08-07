// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseTools.inputs.GetDatabaseToolsEndpointServicesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDatabaseToolsEndpointServicesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDatabaseToolsEndpointServicesPlainArgs Empty = new GetDatabaseToolsEndpointServicesPlainArgs();

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
    private @Nullable List<GetDatabaseToolsEndpointServicesFilter> filters;

    public Optional<List<GetDatabaseToolsEndpointServicesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the entire specified name.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only resources that match the entire specified name.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
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

    private GetDatabaseToolsEndpointServicesPlainArgs() {}

    private GetDatabaseToolsEndpointServicesPlainArgs(GetDatabaseToolsEndpointServicesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDatabaseToolsEndpointServicesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDatabaseToolsEndpointServicesPlainArgs $;

        public Builder() {
            $ = new GetDatabaseToolsEndpointServicesPlainArgs();
        }

        public Builder(GetDatabaseToolsEndpointServicesPlainArgs defaults) {
            $ = new GetDatabaseToolsEndpointServicesPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetDatabaseToolsEndpointServicesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDatabaseToolsEndpointServicesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A filter to return only resources that match the entire specified name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
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

        public GetDatabaseToolsEndpointServicesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDatabaseToolsEndpointServicesPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
