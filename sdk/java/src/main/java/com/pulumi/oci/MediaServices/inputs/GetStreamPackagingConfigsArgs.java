// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.MediaServices.inputs.GetStreamPackagingConfigsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetStreamPackagingConfigsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetStreamPackagingConfigsArgs Empty = new GetStreamPackagingConfigsArgs();

    /**
     * A filter to return only the resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only the resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Unique Stream Distribution Channel identifier.
     * 
     */
    @Import(name="distributionChannelId", required=true)
    private Output<String> distributionChannelId;

    /**
     * @return Unique Stream Distribution Channel identifier.
     * 
     */
    public Output<String> distributionChannelId() {
        return this.distributionChannelId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetStreamPackagingConfigsFilterArgs>> filters;

    public Optional<Output<List<GetStreamPackagingConfigsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only the resources with lifecycleState matching the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only the resources with lifecycleState matching the given lifecycleState.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Unique Stream Packaging Configuration identifier.
     * 
     */
    @Import(name="streamPackagingConfigId")
    private @Nullable Output<String> streamPackagingConfigId;

    /**
     * @return Unique Stream Packaging Configuration identifier.
     * 
     */
    public Optional<Output<String>> streamPackagingConfigId() {
        return Optional.ofNullable(this.streamPackagingConfigId);
    }

    private GetStreamPackagingConfigsArgs() {}

    private GetStreamPackagingConfigsArgs(GetStreamPackagingConfigsArgs $) {
        this.displayName = $.displayName;
        this.distributionChannelId = $.distributionChannelId;
        this.filters = $.filters;
        this.state = $.state;
        this.streamPackagingConfigId = $.streamPackagingConfigId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetStreamPackagingConfigsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetStreamPackagingConfigsArgs $;

        public Builder() {
            $ = new GetStreamPackagingConfigsArgs();
        }

        public Builder(GetStreamPackagingConfigsArgs defaults) {
            $ = new GetStreamPackagingConfigsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only the resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only the resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param distributionChannelId Unique Stream Distribution Channel identifier.
         * 
         * @return builder
         * 
         */
        public Builder distributionChannelId(Output<String> distributionChannelId) {
            $.distributionChannelId = distributionChannelId;
            return this;
        }

        /**
         * @param distributionChannelId Unique Stream Distribution Channel identifier.
         * 
         * @return builder
         * 
         */
        public Builder distributionChannelId(String distributionChannelId) {
            return distributionChannelId(Output.of(distributionChannelId));
        }

        public Builder filters(@Nullable Output<List<GetStreamPackagingConfigsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetStreamPackagingConfigsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetStreamPackagingConfigsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only the resources with lifecycleState matching the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only the resources with lifecycleState matching the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param streamPackagingConfigId Unique Stream Packaging Configuration identifier.
         * 
         * @return builder
         * 
         */
        public Builder streamPackagingConfigId(@Nullable Output<String> streamPackagingConfigId) {
            $.streamPackagingConfigId = streamPackagingConfigId;
            return this;
        }

        /**
         * @param streamPackagingConfigId Unique Stream Packaging Configuration identifier.
         * 
         * @return builder
         * 
         */
        public Builder streamPackagingConfigId(String streamPackagingConfigId) {
            return streamPackagingConfigId(Output.of(streamPackagingConfigId));
        }

        public GetStreamPackagingConfigsArgs build() {
            $.distributionChannelId = Objects.requireNonNull($.distributionChannelId, "expected parameter 'distributionChannelId' to be non-null");
            return $;
        }
    }

}