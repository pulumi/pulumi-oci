// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Dns.inputs.GetResolversFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetResolversArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetResolversArgs Empty = new GetResolversArgs();

    /**
     * The OCID of the compartment the resource belongs to.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment the resource belongs to.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The displayName of a resource.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The displayName of a resource.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetResolversFilterArgs>> filters;

    public Optional<Output<List<GetResolversFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of a resource.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The OCID of a resource.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * Value must be `PRIVATE` when listing private name resolvers.
     * 
     */
    @Import(name="scope", required=true)
    private Output<String> scope;

    /**
     * @return Value must be `PRIVATE` when listing private name resolvers.
     * 
     */
    public Output<String> scope() {
        return this.scope;
    }

    /**
     * The state of a resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The state of a resource.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetResolversArgs() {}

    private GetResolversArgs(GetResolversArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.scope = $.scope;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetResolversArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetResolversArgs $;

        public Builder() {
            $ = new GetResolversArgs();
        }

        public Builder(GetResolversArgs defaults) {
            $ = new GetResolversArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment the resource belongs to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment the resource belongs to.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName The displayName of a resource.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The displayName of a resource.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetResolversFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetResolversFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetResolversFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The OCID of a resource.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The OCID of a resource.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param scope Value must be `PRIVATE` when listing private name resolvers.
         * 
         * @return builder
         * 
         */
        public Builder scope(Output<String> scope) {
            $.scope = scope;
            return this;
        }

        /**
         * @param scope Value must be `PRIVATE` when listing private name resolvers.
         * 
         * @return builder
         * 
         */
        public Builder scope(String scope) {
            return scope(Output.of(scope));
        }

        /**
         * @param state The state of a resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The state of a resource.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetResolversArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.scope = Objects.requireNonNull($.scope, "expected parameter 'scope' to be non-null");
            return $;
        }
    }

}