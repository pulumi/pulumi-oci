// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Streaming.inputs.GetStreamPoolsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetStreamPoolsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetStreamPoolsArgs Empty = new GetStreamPoolsArgs();

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
    private @Nullable Output<List<GetStreamPoolsFilterArgs>> filters;

    public Optional<Output<List<GetStreamPoolsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given ID exactly.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return A filter to return only resources that match the given ID exactly.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources that match the given name exactly.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to return only resources that match the given name exactly.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetStreamPoolsArgs() {}

    private GetStreamPoolsArgs(GetStreamPoolsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.id = $.id;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetStreamPoolsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetStreamPoolsArgs $;

        public Builder() {
            $ = new GetStreamPoolsArgs();
        }

        public Builder(GetStreamPoolsArgs defaults) {
            $ = new GetStreamPoolsArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable Output<List<GetStreamPoolsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetStreamPoolsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetStreamPoolsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id A filter to return only resources that match the given ID exactly.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id A filter to return only resources that match the given ID exactly.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param name A filter to return only resources that match the given name exactly.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the given name exactly.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param state A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetStreamPoolsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}