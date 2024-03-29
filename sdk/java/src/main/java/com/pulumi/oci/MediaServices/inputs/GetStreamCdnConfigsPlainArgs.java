// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MediaServices.inputs.GetStreamCdnConfigsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetStreamCdnConfigsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetStreamCdnConfigsPlainArgs Empty = new GetStreamCdnConfigsPlainArgs();

    /**
     * A filter to return only the resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only the resources that match the entire display name given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The Stream Distribution Channel identifier this CdnConfig belongs to.
     * 
     */
    @Import(name="distributionChannelId", required=true)
    private String distributionChannelId;

    /**
     * @return The Stream Distribution Channel identifier this CdnConfig belongs to.
     * 
     */
    public String distributionChannelId() {
        return this.distributionChannelId;
    }

    @Import(name="filters")
    private @Nullable List<GetStreamCdnConfigsFilter> filters;

    public Optional<List<GetStreamCdnConfigsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique StreamCdnConfig identifier.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return Unique StreamCdnConfig identifier.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only the resources with lifecycleState matching the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only the resources with lifecycleState matching the given lifecycleState.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetStreamCdnConfigsPlainArgs() {}

    private GetStreamCdnConfigsPlainArgs(GetStreamCdnConfigsPlainArgs $) {
        this.displayName = $.displayName;
        this.distributionChannelId = $.distributionChannelId;
        this.filters = $.filters;
        this.id = $.id;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetStreamCdnConfigsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetStreamCdnConfigsPlainArgs $;

        public Builder() {
            $ = new GetStreamCdnConfigsPlainArgs();
        }

        public Builder(GetStreamCdnConfigsPlainArgs defaults) {
            $ = new GetStreamCdnConfigsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only the resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param distributionChannelId The Stream Distribution Channel identifier this CdnConfig belongs to.
         * 
         * @return builder
         * 
         */
        public Builder distributionChannelId(String distributionChannelId) {
            $.distributionChannelId = distributionChannelId;
            return this;
        }

        public Builder filters(@Nullable List<GetStreamCdnConfigsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetStreamCdnConfigsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique StreamCdnConfig identifier.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param state A filter to return only the resources with lifecycleState matching the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetStreamCdnConfigsPlainArgs build() {
            if ($.distributionChannelId == null) {
                throw new MissingRequiredPropertyException("GetStreamCdnConfigsPlainArgs", "distributionChannelId");
            }
            return $;
        }
    }

}
