// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.GetContainersFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetContainersArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetContainersArgs Empty = new GetContainersArgs();

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the container name.
     * 
     */
    @Import(name="containerName")
    private @Nullable Output<String> containerName;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the container name.
     * 
     */
    public Optional<Output<String>> containerName() {
        return Optional.ofNullable(this.containerName);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetContainersFilterArgs>> filters;

    public Optional<Output<List<GetContainersFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * if true, this returns latest version of container.
     * 
     */
    @Import(name="isLatest")
    private @Nullable Output<Boolean> isLatest;

    /**
     * @return if true, this returns latest version of container.
     * 
     */
    public Optional<Output<Boolean>> isLatest() {
        return Optional.ofNullable(this.isLatest);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the container version tag.
     * 
     */
    @Import(name="tagQueryParam")
    private @Nullable Output<String> tagQueryParam;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the container version tag.
     * 
     */
    public Optional<Output<String>> tagQueryParam() {
        return Optional.ofNullable(this.tagQueryParam);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the target workload.
     * 
     */
    @Import(name="targetWorkload")
    private @Nullable Output<String> targetWorkload;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the target workload.
     * 
     */
    public Optional<Output<String>> targetWorkload() {
        return Optional.ofNullable(this.targetWorkload);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the usage.
     * 
     */
    @Import(name="usageQueryParam")
    private @Nullable Output<String> usageQueryParam;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the usage.
     * 
     */
    public Optional<Output<String>> usageQueryParam() {
        return Optional.ofNullable(this.usageQueryParam);
    }

    private GetContainersArgs() {}

    private GetContainersArgs(GetContainersArgs $) {
        this.containerName = $.containerName;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.isLatest = $.isLatest;
        this.state = $.state;
        this.tagQueryParam = $.tagQueryParam;
        this.targetWorkload = $.targetWorkload;
        this.usageQueryParam = $.usageQueryParam;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetContainersArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetContainersArgs $;

        public Builder() {
            $ = new GetContainersArgs();
        }

        public Builder(GetContainersArgs defaults) {
            $ = new GetContainersArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param containerName &lt;b&gt;Filter&lt;/b&gt; results by the container name.
         * 
         * @return builder
         * 
         */
        public Builder containerName(@Nullable Output<String> containerName) {
            $.containerName = containerName;
            return this;
        }

        /**
         * @param containerName &lt;b&gt;Filter&lt;/b&gt; results by the container name.
         * 
         * @return builder
         * 
         */
        public Builder containerName(String containerName) {
            return containerName(Output.of(containerName));
        }

        /**
         * @param displayName &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetContainersFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetContainersFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetContainersFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isLatest if true, this returns latest version of container.
         * 
         * @return builder
         * 
         */
        public Builder isLatest(@Nullable Output<Boolean> isLatest) {
            $.isLatest = isLatest;
            return this;
        }

        /**
         * @param isLatest if true, this returns latest version of container.
         * 
         * @return builder
         * 
         */
        public Builder isLatest(Boolean isLatest) {
            return isLatest(Output.of(isLatest));
        }

        /**
         * @param state &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param tagQueryParam &lt;b&gt;Filter&lt;/b&gt; results by the container version tag.
         * 
         * @return builder
         * 
         */
        public Builder tagQueryParam(@Nullable Output<String> tagQueryParam) {
            $.tagQueryParam = tagQueryParam;
            return this;
        }

        /**
         * @param tagQueryParam &lt;b&gt;Filter&lt;/b&gt; results by the container version tag.
         * 
         * @return builder
         * 
         */
        public Builder tagQueryParam(String tagQueryParam) {
            return tagQueryParam(Output.of(tagQueryParam));
        }

        /**
         * @param targetWorkload &lt;b&gt;Filter&lt;/b&gt; results by the target workload.
         * 
         * @return builder
         * 
         */
        public Builder targetWorkload(@Nullable Output<String> targetWorkload) {
            $.targetWorkload = targetWorkload;
            return this;
        }

        /**
         * @param targetWorkload &lt;b&gt;Filter&lt;/b&gt; results by the target workload.
         * 
         * @return builder
         * 
         */
        public Builder targetWorkload(String targetWorkload) {
            return targetWorkload(Output.of(targetWorkload));
        }

        /**
         * @param usageQueryParam &lt;b&gt;Filter&lt;/b&gt; results by the usage.
         * 
         * @return builder
         * 
         */
        public Builder usageQueryParam(@Nullable Output<String> usageQueryParam) {
            $.usageQueryParam = usageQueryParam;
            return this;
        }

        /**
         * @param usageQueryParam &lt;b&gt;Filter&lt;/b&gt; results by the usage.
         * 
         * @return builder
         * 
         */
        public Builder usageQueryParam(String usageQueryParam) {
            return usageQueryParam(Output.of(usageQueryParam));
        }

        public GetContainersArgs build() {
            return $;
        }
    }

}
