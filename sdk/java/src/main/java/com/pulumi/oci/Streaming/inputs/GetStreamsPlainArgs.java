// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Streaming.inputs.GetStreamsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetStreamsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetStreamsPlainArgs Empty = new GetStreamsPlainArgs();

    /**
     * The OCID of the compartment. Is exclusive with the `streamPoolId` parameter. One of them is required.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The OCID of the compartment. Is exclusive with the `streamPoolId` parameter. One of them is required.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable List<GetStreamsFilter> filters;

    public Optional<List<GetStreamsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the given ID exactly.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return A filter to return only resources that match the given ID exactly.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources that match the given name exactly.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only resources that match the given name exactly.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The OCID of the stream pool. Is exclusive with the `compartmentId` parameter. One of them is required.
     * 
     */
    @Import(name="streamPoolId")
    private @Nullable String streamPoolId;

    /**
     * @return The OCID of the stream pool. Is exclusive with the `compartmentId` parameter. One of them is required.
     * 
     */
    public Optional<String> streamPoolId() {
        return Optional.ofNullable(this.streamPoolId);
    }

    private GetStreamsPlainArgs() {}

    private GetStreamsPlainArgs(GetStreamsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.id = $.id;
        this.name = $.name;
        this.state = $.state;
        this.streamPoolId = $.streamPoolId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetStreamsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetStreamsPlainArgs $;

        public Builder() {
            $ = new GetStreamsPlainArgs();
        }

        public Builder(GetStreamsPlainArgs defaults) {
            $ = new GetStreamsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment. Is exclusive with the `streamPoolId` parameter. One of them is required.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetStreamsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetStreamsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id A filter to return only resources that match the given ID exactly.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the given name exactly.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param state A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param streamPoolId The OCID of the stream pool. Is exclusive with the `compartmentId` parameter. One of them is required.
         * 
         * @return builder
         * 
         */
        public Builder streamPoolId(@Nullable String streamPoolId) {
            $.streamPoolId = streamPoolId;
            return this;
        }

        public GetStreamsPlainArgs build() {
            return $;
        }
    }

}