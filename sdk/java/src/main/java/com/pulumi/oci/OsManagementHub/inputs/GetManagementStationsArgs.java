// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagementHub.inputs.GetManagementStationsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagementStationsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagementStationsArgs Empty = new GetManagementStationsArgs();

    /**
     * The OCID of the compartment that contains the resources to list.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment that contains the resources to list.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * A filter to return resources that may partially match the given display name.
     * 
     */
    @Import(name="displayNameContains")
    private @Nullable Output<String> displayNameContains;

    /**
     * @return A filter to return resources that may partially match the given display name.
     * 
     */
    public Optional<Output<String>> displayNameContains() {
        return Optional.ofNullable(this.displayNameContains);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetManagementStationsFilterArgs>> filters;

    public Optional<Output<List<GetManagementStationsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the management station.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The OCID of the management station.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The OCID of the managed instance for which to list resources.
     * 
     */
    @Import(name="managedInstanceId")
    private @Nullable Output<String> managedInstanceId;

    /**
     * @return The OCID of the managed instance for which to list resources.
     * 
     */
    public Optional<Output<String>> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }

    /**
     * The current lifecycle state for the object.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state for the object.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetManagementStationsArgs() {}

    private GetManagementStationsArgs(GetManagementStationsArgs $) {
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
    public static Builder builder(GetManagementStationsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagementStationsArgs $;

        public Builder() {
            $ = new GetManagementStationsArgs();
        }

        public Builder(GetManagementStationsArgs defaults) {
            $ = new GetManagementStationsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment that contains the resources to list.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment that contains the resources to list.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param displayNameContains A filter to return resources that may partially match the given display name.
         * 
         * @return builder
         * 
         */
        public Builder displayNameContains(@Nullable Output<String> displayNameContains) {
            $.displayNameContains = displayNameContains;
            return this;
        }

        /**
         * @param displayNameContains A filter to return resources that may partially match the given display name.
         * 
         * @return builder
         * 
         */
        public Builder displayNameContains(String displayNameContains) {
            return displayNameContains(Output.of(displayNameContains));
        }

        public Builder filters(@Nullable Output<List<GetManagementStationsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagementStationsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagementStationsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The OCID of the management station.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The OCID of the management station.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param managedInstanceId The OCID of the managed instance for which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(@Nullable Output<String> managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param managedInstanceId The OCID of the managed instance for which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(String managedInstanceId) {
            return managedInstanceId(Output.of(managedInstanceId));
        }

        /**
         * @param state The current lifecycle state for the object.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state for the object.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetManagementStationsArgs build() {
            return $;
        }
    }

}