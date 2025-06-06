// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetSoftwareUpdate.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FsuCycleBatchingStrategyArgs extends com.pulumi.resources.ResourceArgs {

    public static final FsuCycleBatchingStrategyArgs Empty = new FsuCycleBatchingStrategyArgs();

    /**
     * (Updatable) True to force rolling patching.
     * 
     */
    @Import(name="isForceRolling")
    private @Nullable Output<Boolean> isForceRolling;

    /**
     * @return (Updatable) True to force rolling patching.
     * 
     */
    public Optional<Output<Boolean>> isForceRolling() {
        return Optional.ofNullable(this.isForceRolling);
    }

    /**
     * (Updatable) True to wait for customer to resume the Apply Action once the first half is done. False to automatically patch the second half.
     * 
     */
    @Import(name="isWaitForBatchResume")
    private @Nullable Output<Boolean> isWaitForBatchResume;

    /**
     * @return (Updatable) True to wait for customer to resume the Apply Action once the first half is done. False to automatically patch the second half.
     * 
     */
    public Optional<Output<Boolean>> isWaitForBatchResume() {
        return Optional.ofNullable(this.isWaitForBatchResume);
    }

    /**
     * (Updatable) Percentage of availability in the service during the Patch operation.
     * 
     */
    @Import(name="percentage")
    private @Nullable Output<Integer> percentage;

    /**
     * @return (Updatable) Percentage of availability in the service during the Patch operation.
     * 
     */
    public Optional<Output<Integer>> percentage() {
        return Optional.ofNullable(this.percentage);
    }

    /**
     * (Updatable) Supported batching strategies.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) Supported batching strategies.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private FsuCycleBatchingStrategyArgs() {}

    private FsuCycleBatchingStrategyArgs(FsuCycleBatchingStrategyArgs $) {
        this.isForceRolling = $.isForceRolling;
        this.isWaitForBatchResume = $.isWaitForBatchResume;
        this.percentage = $.percentage;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FsuCycleBatchingStrategyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FsuCycleBatchingStrategyArgs $;

        public Builder() {
            $ = new FsuCycleBatchingStrategyArgs();
        }

        public Builder(FsuCycleBatchingStrategyArgs defaults) {
            $ = new FsuCycleBatchingStrategyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isForceRolling (Updatable) True to force rolling patching.
         * 
         * @return builder
         * 
         */
        public Builder isForceRolling(@Nullable Output<Boolean> isForceRolling) {
            $.isForceRolling = isForceRolling;
            return this;
        }

        /**
         * @param isForceRolling (Updatable) True to force rolling patching.
         * 
         * @return builder
         * 
         */
        public Builder isForceRolling(Boolean isForceRolling) {
            return isForceRolling(Output.of(isForceRolling));
        }

        /**
         * @param isWaitForBatchResume (Updatable) True to wait for customer to resume the Apply Action once the first half is done. False to automatically patch the second half.
         * 
         * @return builder
         * 
         */
        public Builder isWaitForBatchResume(@Nullable Output<Boolean> isWaitForBatchResume) {
            $.isWaitForBatchResume = isWaitForBatchResume;
            return this;
        }

        /**
         * @param isWaitForBatchResume (Updatable) True to wait for customer to resume the Apply Action once the first half is done. False to automatically patch the second half.
         * 
         * @return builder
         * 
         */
        public Builder isWaitForBatchResume(Boolean isWaitForBatchResume) {
            return isWaitForBatchResume(Output.of(isWaitForBatchResume));
        }

        /**
         * @param percentage (Updatable) Percentage of availability in the service during the Patch operation.
         * 
         * @return builder
         * 
         */
        public Builder percentage(@Nullable Output<Integer> percentage) {
            $.percentage = percentage;
            return this;
        }

        /**
         * @param percentage (Updatable) Percentage of availability in the service during the Patch operation.
         * 
         * @return builder
         * 
         */
        public Builder percentage(Integer percentage) {
            return percentage(Output.of(percentage));
        }

        /**
         * @param type (Updatable) Supported batching strategies.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Supported batching strategies.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public FsuCycleBatchingStrategyArgs build() {
            return $;
        }
    }

}
