// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.GetManagementStationsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagementStationsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagementStationsPlainArgs Empty = new GetManagementStationsPlainArgs();

    /**
     * The OCID of the compartment that contains the resources to list.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The OCID of the compartment that contains the resources to list.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * A filter to return resources that may partially match the given display name.
     * 
     */
    @Import(name="displayNameContains")
    private @Nullable String displayNameContains;

    /**
     * @return A filter to return resources that may partially match the given display name.
     * 
     */
    public Optional<String> displayNameContains() {
        return Optional.ofNullable(this.displayNameContains);
    }

    @Import(name="filters")
    private @Nullable List<GetManagementStationsFilter> filters;

    public Optional<List<GetManagementStationsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the management station.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return The OCID of the management station.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The OCID of the managed instance for which to list resources.
     * 
     */
    @Import(name="managedInstanceId")
    private @Nullable String managedInstanceId;

    /**
     * @return The OCID of the managed instance for which to list resources.
     * 
     */
    public Optional<String> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }

    /**
     * The current lifecycle state for the object.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current lifecycle state for the object.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetManagementStationsPlainArgs() {}

    private GetManagementStationsPlainArgs(GetManagementStationsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.displayNameContains = $.displayNameContains;
        this.filters = $.filters;
        this.id = $.id;
        this.managedInstanceId = $.managedInstanceId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagementStationsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagementStationsPlainArgs $;

        public Builder() {
            $ = new GetManagementStationsPlainArgs();
        }

        public Builder(GetManagementStationsPlainArgs defaults) {
            $ = new GetManagementStationsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment that contains the resources to list.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayNameContains A filter to return resources that may partially match the given display name.
         * 
         * @return builder
         * 
         */
        public Builder displayNameContains(@Nullable String displayNameContains) {
            $.displayNameContains = displayNameContains;
            return this;
        }

        public Builder filters(@Nullable List<GetManagementStationsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetManagementStationsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The OCID of the management station.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param managedInstanceId The OCID of the managed instance for which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(@Nullable String managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param state The current lifecycle state for the object.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetManagementStationsPlainArgs build() {
            return $;
        }
    }

}