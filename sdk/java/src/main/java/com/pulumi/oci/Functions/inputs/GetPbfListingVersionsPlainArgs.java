// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Functions.inputs.GetPbfListingVersionsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPbfListingVersionsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPbfListingVersionsPlainArgs Empty = new GetPbfListingVersionsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetPbfListingVersionsFilter> filters;

    public Optional<List<GetPbfListingVersionsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Matches the current version (the most recently added version with an Active  lifecycleState) associated with a PbfListing.
     * 
     */
    @Import(name="isCurrentVersion")
    private @Nullable Boolean isCurrentVersion;

    /**
     * @return Matches the current version (the most recently added version with an Active  lifecycleState) associated with a PbfListing.
     * 
     */
    public Optional<Boolean> isCurrentVersion() {
        return Optional.ofNullable(this.isCurrentVersion);
    }

    /**
     * Matches a PbfListingVersion based on a provided semantic version name for a PbfListingVersion.  Each PbfListingVersion name is unique with respect to its associated PbfListing.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return Matches a PbfListingVersion based on a provided semantic version name for a PbfListingVersion.  Each PbfListingVersion name is unique with respect to its associated PbfListing.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * unique PbfListing identifier
     * 
     */
    @Import(name="pbfListingId", required=true)
    private String pbfListingId;

    /**
     * @return unique PbfListing identifier
     * 
     */
    public String pbfListingId() {
        return this.pbfListingId;
    }

    /**
     * unique PbfListingVersion identifier
     * 
     */
    @Import(name="pbfListingVersionId")
    private @Nullable String pbfListingVersionId;

    /**
     * @return unique PbfListingVersion identifier
     * 
     */
    public Optional<String> pbfListingVersionId() {
        return Optional.ofNullable(this.pbfListingVersionId);
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

    private GetPbfListingVersionsPlainArgs() {}

    private GetPbfListingVersionsPlainArgs(GetPbfListingVersionsPlainArgs $) {
        this.filters = $.filters;
        this.isCurrentVersion = $.isCurrentVersion;
        this.name = $.name;
        this.pbfListingId = $.pbfListingId;
        this.pbfListingVersionId = $.pbfListingVersionId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPbfListingVersionsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPbfListingVersionsPlainArgs $;

        public Builder() {
            $ = new GetPbfListingVersionsPlainArgs();
        }

        public Builder(GetPbfListingVersionsPlainArgs defaults) {
            $ = new GetPbfListingVersionsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetPbfListingVersionsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetPbfListingVersionsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isCurrentVersion Matches the current version (the most recently added version with an Active  lifecycleState) associated with a PbfListing.
         * 
         * @return builder
         * 
         */
        public Builder isCurrentVersion(@Nullable Boolean isCurrentVersion) {
            $.isCurrentVersion = isCurrentVersion;
            return this;
        }

        /**
         * @param name Matches a PbfListingVersion based on a provided semantic version name for a PbfListingVersion.  Each PbfListingVersion name is unique with respect to its associated PbfListing.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param pbfListingId unique PbfListing identifier
         * 
         * @return builder
         * 
         */
        public Builder pbfListingId(String pbfListingId) {
            $.pbfListingId = pbfListingId;
            return this;
        }

        /**
         * @param pbfListingVersionId unique PbfListingVersion identifier
         * 
         * @return builder
         * 
         */
        public Builder pbfListingVersionId(@Nullable String pbfListingVersionId) {
            $.pbfListingVersionId = pbfListingVersionId;
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

        public GetPbfListingVersionsPlainArgs build() {
            $.pbfListingId = Objects.requireNonNull($.pbfListingId, "expected parameter 'pbfListingId' to be non-null");
            return $;
        }
    }

}