// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FunctionProvisionedConcurrencyConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final FunctionProvisionedConcurrencyConfigArgs Empty = new FunctionProvisionedConcurrencyConfigArgs();

    /**
     * (Updatable)
     * 
     */
    @Import(name="count")
    private @Nullable Output<Integer> count;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<Integer>> count() {
        return Optional.ofNullable(this.count);
    }

    /**
     * (Updatable) The strategy for provisioned concurrency to be used.
     * 
     */
    @Import(name="strategy", required=true)
    private Output<String> strategy;

    /**
     * @return (Updatable) The strategy for provisioned concurrency to be used.
     * 
     */
    public Output<String> strategy() {
        return this.strategy;
    }

    private FunctionProvisionedConcurrencyConfigArgs() {}

    private FunctionProvisionedConcurrencyConfigArgs(FunctionProvisionedConcurrencyConfigArgs $) {
        this.count = $.count;
        this.strategy = $.strategy;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FunctionProvisionedConcurrencyConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FunctionProvisionedConcurrencyConfigArgs $;

        public Builder() {
            $ = new FunctionProvisionedConcurrencyConfigArgs();
        }

        public Builder(FunctionProvisionedConcurrencyConfigArgs defaults) {
            $ = new FunctionProvisionedConcurrencyConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param count (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder count(@Nullable Output<Integer> count) {
            $.count = count;
            return this;
        }

        /**
         * @param count (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder count(Integer count) {
            return count(Output.of(count));
        }

        /**
         * @param strategy (Updatable) The strategy for provisioned concurrency to be used.
         * 
         * @return builder
         * 
         */
        public Builder strategy(Output<String> strategy) {
            $.strategy = strategy;
            return this;
        }

        /**
         * @param strategy (Updatable) The strategy for provisioned concurrency to be used.
         * 
         * @return builder
         * 
         */
        public Builder strategy(String strategy) {
            return strategy(Output.of(strategy));
        }

        public FunctionProvisionedConcurrencyConfigArgs build() {
            $.strategy = Objects.requireNonNull($.strategy, "expected parameter 'strategy' to be non-null");
            return $;
        }
    }

}