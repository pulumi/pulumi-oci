// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Functions.inputs.GetFusionEnvironmentServiceAttachmentsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetFusionEnvironmentServiceAttachmentsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFusionEnvironmentServiceAttachmentsArgs Empty = new GetFusionEnvironmentServiceAttachmentsArgs();

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetFusionEnvironmentServiceAttachmentsFilterArgs>> filters;

    public Optional<Output<List<GetFusionEnvironmentServiceAttachmentsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * unique FusionEnvironment identifier
     * 
     */
    @Import(name="fusionEnvironmentId", required=true)
    private Output<String> fusionEnvironmentId;

    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public Output<String> fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }

    /**
     * A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    @Import(name="serviceInstanceType")
    private @Nullable Output<String> serviceInstanceType;

    /**
     * @return A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    public Optional<Output<String>> serviceInstanceType() {
        return Optional.ofNullable(this.serviceInstanceType);
    }

    /**
     * A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter that returns all resources that match the specified lifecycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetFusionEnvironmentServiceAttachmentsArgs() {}

    private GetFusionEnvironmentServiceAttachmentsArgs(GetFusionEnvironmentServiceAttachmentsArgs $) {
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.fusionEnvironmentId = $.fusionEnvironmentId;
        this.serviceInstanceType = $.serviceInstanceType;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFusionEnvironmentServiceAttachmentsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFusionEnvironmentServiceAttachmentsArgs $;

        public Builder() {
            $ = new GetFusionEnvironmentServiceAttachmentsArgs();
        }

        public Builder(GetFusionEnvironmentServiceAttachmentsArgs defaults) {
            $ = new GetFusionEnvironmentServiceAttachmentsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetFusionEnvironmentServiceAttachmentsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetFusionEnvironmentServiceAttachmentsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetFusionEnvironmentServiceAttachmentsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(Output<String> fusionEnvironmentId) {
            $.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            return fusionEnvironmentId(Output.of(fusionEnvironmentId));
        }

        /**
         * @param serviceInstanceType A filter that returns all resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder serviceInstanceType(@Nullable Output<String> serviceInstanceType) {
            $.serviceInstanceType = serviceInstanceType;
            return this;
        }

        /**
         * @param serviceInstanceType A filter that returns all resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder serviceInstanceType(String serviceInstanceType) {
            return serviceInstanceType(Output.of(serviceInstanceType));
        }

        /**
         * @param state A filter that returns all resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter that returns all resources that match the specified lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetFusionEnvironmentServiceAttachmentsArgs build() {
            $.fusionEnvironmentId = Objects.requireNonNull($.fusionEnvironmentId, "expected parameter 'fusionEnvironmentId' to be non-null");
            return $;
        }
    }

}