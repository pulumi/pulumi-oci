// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Functions.inputs.GetPbfListingsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPbfListingsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPbfListingsPlainArgs Empty = new GetPbfListingsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetPbfListingsFilter> filters;

    public Optional<List<GetPbfListingsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the entire PBF name given.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only resources that match the entire PBF name given.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter to return only resources that contain the supplied filter text in the PBF name given.
     * 
     */
    @Import(name="nameContains")
    private @Nullable String nameContains;

    /**
     * @return A filter to return only resources that contain the supplied filter text in the PBF name given.
     * 
     */
    public Optional<String> nameContains() {
        return Optional.ofNullable(this.nameContains);
    }

    /**
     * A filter to return only resources that start with the supplied filter text in the PBF name given.
     * 
     */
    @Import(name="nameStartsWith")
    private @Nullable String nameStartsWith;

    /**
     * @return A filter to return only resources that start with the supplied filter text in the PBF name given.
     * 
     */
    public Optional<String> nameStartsWith() {
        return Optional.ofNullable(this.nameStartsWith);
    }

    /**
     * unique PbfListing identifier
     * 
     */
    @Import(name="pbfListingId")
    private @Nullable String pbfListingId;

    /**
     * @return unique PbfListing identifier
     * 
     */
    public Optional<String> pbfListingId() {
        return Optional.ofNullable(this.pbfListingId);
    }

    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only resources that match the service trigger sources of a PBF.
     * 
     */
    @Import(name="triggers")
    private @Nullable List<String> triggers;

    /**
     * @return A filter to return only resources that match the service trigger sources of a PBF.
     * 
     */
    public Optional<List<String>> triggers() {
        return Optional.ofNullable(this.triggers);
    }

    private GetPbfListingsPlainArgs() {}

    private GetPbfListingsPlainArgs(GetPbfListingsPlainArgs $) {
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
    public static Builder builder(GetPbfListingsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPbfListingsPlainArgs $;

        public Builder() {
            $ = new GetPbfListingsPlainArgs();
        }

        public Builder(GetPbfListingsPlainArgs defaults) {
            $ = new GetPbfListingsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetPbfListingsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetPbfListingsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A filter to return only resources that match the entire PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param nameContains A filter to return only resources that contain the supplied filter text in the PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder nameContains(@Nullable String nameContains) {
            $.nameContains = nameContains;
            return this;
        }

        /**
         * @param nameStartsWith A filter to return only resources that start with the supplied filter text in the PBF name given.
         * 
         * @return builder
         * 
         */
        public Builder nameStartsWith(@Nullable String nameStartsWith) {
            $.nameStartsWith = nameStartsWith;
            return this;
        }

        /**
         * @param pbfListingId unique PbfListing identifier
         * 
         * @return builder
         * 
         */
        public Builder pbfListingId(@Nullable String pbfListingId) {
            $.pbfListingId = pbfListingId;
            return this;
        }

        /**
         * @param state A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param triggers A filter to return only resources that match the service trigger sources of a PBF.
         * 
         * @return builder
         * 
         */
        public Builder triggers(@Nullable List<String> triggers) {
            $.triggers = triggers;
            return this;
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

        public GetPbfListingsPlainArgs build() {
            return $;
        }
    }

}