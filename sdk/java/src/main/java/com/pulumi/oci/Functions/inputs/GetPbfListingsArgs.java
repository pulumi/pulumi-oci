// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Functions.inputs.GetPbfListingsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPbfListingsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPbfListingsArgs Empty = new GetPbfListingsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetPbfListingsFilterArgs>> filters;

    public Optional<Output<List<GetPbfListingsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the entire PBF name given.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to return only resources that match the entire PBF name given.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter to return only resources that contain the supplied filter text in the PBF name given.
     * 
     */
    @Import(name="nameContains")
    private @Nullable Output<String> nameContains;

    /**
     * @return A filter to return only resources that contain the supplied filter text in the PBF name given.
     * 
     */
    public Optional<Output<String>> nameContains() {
        return Optional.ofNullable(this.nameContains);
    }

    /**
     * A filter to return only resources that start with the supplied filter text in the PBF name given.
     * 
     */
    @Import(name="nameStartsWith")
    private @Nullable Output<String> nameStartsWith;

    /**
     * @return A filter to return only resources that start with the supplied filter text in the PBF name given.
     * 
     */
    public Optional<Output<String>> nameStartsWith() {
        return Optional.ofNullable(this.nameStartsWith);
    }

    /**
     * unique PbfListing identifier
     * 
     */
    @Import(name="pbfListingId")
    private @Nullable Output<String> pbfListingId;

    /**
     * @return unique PbfListing identifier
     * 
     */
    public Optional<Output<String>> pbfListingId() {
        return Optional.ofNullable(this.pbfListingId);
    }

    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only resources that match the service trigger sources of a PBF.
     * 
     */
    @Import(name="triggers")
    private @Nullable Output<List<String>> triggers;

    /**
     * @return A filter to return only resources that match the service trigger sources of a PBF.
     * 
     */
    public Optional<Output<List<String>>> triggers() {
        return Optional.ofNullable(this.triggers);
    }

    private GetPbfListingsArgs() {}

    private GetPbfListingsArgs(GetPbfListingsArgs $) {
        this.filters = $.filters;
        this.name = $.name;
        this.nameContains = $.nameContains;
        this.nameStartsWith = $.nameStartsWith;
        this.pbfListingId = $.pbfListingId;
        this.state = $.state;
        this.triggers = $.triggers;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPbfListingsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPbfListingsArgs $;

        public Builder() {
            $ = new GetPbfListingsArgs();
        }

        public Builder(GetPbfListingsArgs defaults) {
            $ = new GetPbfListingsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetPbfListingsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetPbfListingsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetPbfListingsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A filter to return only resources that match the entire PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the entire PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param nameContains A filter to return only resources that contain the supplied filter text in the PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder nameContains(@Nullable Output<String> nameContains) {
            $.nameContains = nameContains;
            return this;
        }

        /**
         * @param nameContains A filter to return only resources that contain the supplied filter text in the PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder nameContains(String nameContains) {
            return nameContains(Output.of(nameContains));
        }

        /**
         * @param nameStartsWith A filter to return only resources that start with the supplied filter text in the PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder nameStartsWith(@Nullable Output<String> nameStartsWith) {
            $.nameStartsWith = nameStartsWith;
            return this;
        }

        /**
         * @param nameStartsWith A filter to return only resources that start with the supplied filter text in the PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder nameStartsWith(String nameStartsWith) {
            return nameStartsWith(Output.of(nameStartsWith));
        }

        /**
         * @param pbfListingId unique PbfListing identifier
         * 
         * @return builder
         * 
         */
        public Builder pbfListingId(@Nullable Output<String> pbfListingId) {
            $.pbfListingId = pbfListingId;
            return this;
        }

        /**
         * @param pbfListingId unique PbfListing identifier
         * 
         * @return builder
         * 
         */
        public Builder pbfListingId(String pbfListingId) {
            return pbfListingId(Output.of(pbfListingId));
        }

        /**
         * @param state A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param triggers A filter to return only resources that match the service trigger sources of a PBF.
         * 
         * @return builder
         * 
         */
        public Builder triggers(@Nullable Output<List<String>> triggers) {
            $.triggers = triggers;
            return this;
        }

        /**
         * @param triggers A filter to return only resources that match the service trigger sources of a PBF.
         * 
         * @return builder
         * 
         */
        public Builder triggers(List<String> triggers) {
            return triggers(Output.of(triggers));
        }

        /**
         * @param triggers A filter to return only resources that match the service trigger sources of a PBF.
         * 
         * @return builder
         * 
         */
        public Builder triggers(String... triggers) {
            return triggers(List.of(triggers));
        }

        public GetPbfListingsArgs build() {
            return $;
        }
    }

}