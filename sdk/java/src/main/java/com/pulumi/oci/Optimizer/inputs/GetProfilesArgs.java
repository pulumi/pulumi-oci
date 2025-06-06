// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Optimizer.inputs.GetProfilesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetProfilesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProfilesArgs Empty = new GetProfilesArgs();

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

    @Import(name="filters")
    private @Nullable Output<List<GetProfilesFilterArgs>> filters;

    public Optional<Output<List<GetProfilesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Optional. A filter that returns results that match the name specified.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Optional. A filter that returns results that match the name specified.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter that returns results that match the lifecycle state specified.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter that returns results that match the lifecycle state specified.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetProfilesArgs() {}

    private GetProfilesArgs(GetProfilesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProfilesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProfilesArgs $;

        public Builder() {
            $ = new GetProfilesArgs();
        }

        public Builder(GetProfilesArgs defaults) {
            $ = new GetProfilesArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable Output<List<GetProfilesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetProfilesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetProfilesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name Optional. A filter that returns results that match the name specified.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Optional. A filter that returns results that match the name specified.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param state A filter that returns results that match the lifecycle state specified.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter that returns results that match the lifecycle state specified.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetProfilesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetProfilesArgs", "compartmentId");
            }
            return $;
        }
    }

}
