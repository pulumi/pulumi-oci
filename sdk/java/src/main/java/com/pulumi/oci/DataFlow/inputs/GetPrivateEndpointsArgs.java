// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataFlow.inputs.GetPrivateEndpointsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPrivateEndpointsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPrivateEndpointsArgs Empty = new GetPrivateEndpointsArgs();

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The query parameter for the Spark application name. Note: At a time only one optional filter can be used with `compartment_id` to get the list of Private Endpoint resources.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The query parameter for the Spark application name. Note: At a time only one optional filter can be used with `compartment_id` to get the list of Private Endpoint resources.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The displayName prefix.
     * 
     */
    @Import(name="displayNameStartsWith")
    private @Nullable Output<String> displayNameStartsWith;

    /**
     * @return The displayName prefix.
     * 
     */
    public Optional<Output<String>> displayNameStartsWith() {
        return Optional.ofNullable(this.displayNameStartsWith);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetPrivateEndpointsFilterArgs>> filters;

    public Optional<Output<List<GetPrivateEndpointsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the user who created the resource.
     * 
     */
    @Import(name="ownerPrincipalId")
    private @Nullable Output<String> ownerPrincipalId;

    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    public Optional<Output<String>> ownerPrincipalId() {
        return Optional.ofNullable(this.ownerPrincipalId);
    }

    /**
     * The LifecycleState of the private endpoint.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The LifecycleState of the private endpoint.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetPrivateEndpointsArgs() {}

    private GetPrivateEndpointsArgs(GetPrivateEndpointsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.displayNameStartsWith = $.displayNameStartsWith;
        this.filters = $.filters;
        this.ownerPrincipalId = $.ownerPrincipalId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPrivateEndpointsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPrivateEndpointsArgs $;

        public Builder() {
            $ = new GetPrivateEndpointsArgs();
        }

        public Builder(GetPrivateEndpointsArgs defaults) {
            $ = new GetPrivateEndpointsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName The query parameter for the Spark application name. Note: At a time only one optional filter can be used with `compartment_id` to get the list of Private Endpoint resources.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The query parameter for the Spark application name. Note: At a time only one optional filter can be used with `compartment_id` to get the list of Private Endpoint resources.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param displayNameStartsWith The displayName prefix.
         * 
         * @return builder
         * 
         */
        public Builder displayNameStartsWith(@Nullable Output<String> displayNameStartsWith) {
            $.displayNameStartsWith = displayNameStartsWith;
            return this;
        }

        /**
         * @param displayNameStartsWith The displayName prefix.
         * 
         * @return builder
         * 
         */
        public Builder displayNameStartsWith(String displayNameStartsWith) {
            return displayNameStartsWith(Output.of(displayNameStartsWith));
        }

        public Builder filters(@Nullable Output<List<GetPrivateEndpointsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetPrivateEndpointsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetPrivateEndpointsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param ownerPrincipalId The OCID of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder ownerPrincipalId(@Nullable Output<String> ownerPrincipalId) {
            $.ownerPrincipalId = ownerPrincipalId;
            return this;
        }

        /**
         * @param ownerPrincipalId The OCID of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder ownerPrincipalId(String ownerPrincipalId) {
            return ownerPrincipalId(Output.of(ownerPrincipalId));
        }

        /**
         * @param state The LifecycleState of the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The LifecycleState of the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetPrivateEndpointsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetPrivateEndpointsArgs", "compartmentId");
            }
            return $;
        }
    }

}
