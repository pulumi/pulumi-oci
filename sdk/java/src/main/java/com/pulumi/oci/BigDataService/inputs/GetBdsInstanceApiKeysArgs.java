// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.BigDataService.inputs.GetBdsInstanceApiKeysFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBdsInstanceApiKeysArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBdsInstanceApiKeysArgs Empty = new GetBdsInstanceApiKeysArgs();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId", required=true)
    private Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Output<String> bdsInstanceId() {
        return this.bdsInstanceId;
    }

    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetBdsInstanceApiKeysFilterArgs>> filters;

    public Optional<Output<List<GetBdsInstanceApiKeysFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The current status of the API key.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current status of the API key.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The user OCID for which this API key was created.
     * 
     */
    @Import(name="userId")
    private @Nullable Output<String> userId;

    /**
     * @return The user OCID for which this API key was created.
     * 
     */
    public Optional<Output<String>> userId() {
        return Optional.ofNullable(this.userId);
    }

    private GetBdsInstanceApiKeysArgs() {}

    private GetBdsInstanceApiKeysArgs(GetBdsInstanceApiKeysArgs $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
        this.userId = $.userId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBdsInstanceApiKeysArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBdsInstanceApiKeysArgs $;

        public Builder() {
            $ = new GetBdsInstanceApiKeysArgs();
        }

        public Builder(GetBdsInstanceApiKeysArgs defaults) {
            $ = new GetBdsInstanceApiKeysArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(Output<String> bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            return bdsInstanceId(Output.of(bdsInstanceId));
        }

        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetBdsInstanceApiKeysFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetBdsInstanceApiKeysFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetBdsInstanceApiKeysFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state The current status of the API key.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current status of the API key.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param userId The user OCID for which this API key was created.
         * 
         * @return builder
         * 
         */
        public Builder userId(@Nullable Output<String> userId) {
            $.userId = userId;
            return this;
        }

        /**
         * @param userId The user OCID for which this API key was created.
         * 
         * @return builder
         * 
         */
        public Builder userId(String userId) {
            return userId(Output.of(userId));
        }

        public GetBdsInstanceApiKeysArgs build() {
            $.bdsInstanceId = Objects.requireNonNull($.bdsInstanceId, "expected parameter 'bdsInstanceId' to be non-null");
            return $;
        }
    }

}