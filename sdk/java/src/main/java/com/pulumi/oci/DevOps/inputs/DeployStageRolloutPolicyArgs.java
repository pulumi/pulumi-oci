// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployStageRolloutPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployStageRolloutPolicyArgs Empty = new DeployStageRolloutPolicyArgs();

    /**
     * (Updatable) The number that will be used to determine how many instances will be deployed concurrently.
     * 
     */
    @Import(name="batchCount")
    private @Nullable Output<Integer> batchCount;

    /**
     * @return (Updatable) The number that will be used to determine how many instances will be deployed concurrently.
     * 
     */
    public Optional<Output<Integer>> batchCount() {
        return Optional.ofNullable(this.batchCount);
    }

    /**
     * (Updatable) The duration of delay between batch rollout. The default delay is 1 minute.
     * 
     */
    @Import(name="batchDelayInSeconds")
    private @Nullable Output<Integer> batchDelayInSeconds;

    /**
     * @return (Updatable) The duration of delay between batch rollout. The default delay is 1 minute.
     * 
     */
    public Optional<Output<Integer>> batchDelayInSeconds() {
        return Optional.ofNullable(this.batchDelayInSeconds);
    }

    /**
     * (Updatable) The percentage that will be used to determine how many instances will be deployed concurrently.
     * 
     */
    @Import(name="batchPercentage")
    private @Nullable Output<Integer> batchPercentage;

    /**
     * @return (Updatable) The percentage that will be used to determine how many instances will be deployed concurrently.
     * 
     */
    public Optional<Output<Integer>> batchPercentage() {
        return Optional.ofNullable(this.batchPercentage);
    }

    /**
     * (Updatable) The type of policy used for rolling out a deployment stage.
     * 
     */
    @Import(name="policyType")
    private @Nullable Output<String> policyType;

    /**
     * @return (Updatable) The type of policy used for rolling out a deployment stage.
     * 
     */
    public Optional<Output<String>> policyType() {
        return Optional.ofNullable(this.policyType);
    }

    /**
     * (Updatable) Indicates the criteria to stop.
     * 
     */
    @Import(name="rampLimitPercent")
    private @Nullable Output<Double> rampLimitPercent;

    /**
     * @return (Updatable) Indicates the criteria to stop.
     * 
     */
    public Optional<Output<Double>> rampLimitPercent() {
        return Optional.ofNullable(this.rampLimitPercent);
    }

    private DeployStageRolloutPolicyArgs() {}

    private DeployStageRolloutPolicyArgs(DeployStageRolloutPolicyArgs $) {
        this.batchCount = $.batchCount;
        this.batchDelayInSeconds = $.batchDelayInSeconds;
        this.batchPercentage = $.batchPercentage;
        this.policyType = $.policyType;
        this.rampLimitPercent = $.rampLimitPercent;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployStageRolloutPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployStageRolloutPolicyArgs $;

        public Builder() {
            $ = new DeployStageRolloutPolicyArgs();
        }

        public Builder(DeployStageRolloutPolicyArgs defaults) {
            $ = new DeployStageRolloutPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param batchCount (Updatable) The number that will be used to determine how many instances will be deployed concurrently.
         * 
         * @return builder
         * 
         */
        public Builder batchCount(@Nullable Output<Integer> batchCount) {
            $.batchCount = batchCount;
            return this;
        }

        /**
         * @param batchCount (Updatable) The number that will be used to determine how many instances will be deployed concurrently.
         * 
         * @return builder
         * 
         */
        public Builder batchCount(Integer batchCount) {
            return batchCount(Output.of(batchCount));
        }

        /**
         * @param batchDelayInSeconds (Updatable) The duration of delay between batch rollout. The default delay is 1 minute.
         * 
         * @return builder
         * 
         */
        public Builder batchDelayInSeconds(@Nullable Output<Integer> batchDelayInSeconds) {
            $.batchDelayInSeconds = batchDelayInSeconds;
            return this;
        }

        /**
         * @param batchDelayInSeconds (Updatable) The duration of delay between batch rollout. The default delay is 1 minute.
         * 
         * @return builder
         * 
         */
        public Builder batchDelayInSeconds(Integer batchDelayInSeconds) {
            return batchDelayInSeconds(Output.of(batchDelayInSeconds));
        }

        /**
         * @param batchPercentage (Updatable) The percentage that will be used to determine how many instances will be deployed concurrently.
         * 
         * @return builder
         * 
         */
        public Builder batchPercentage(@Nullable Output<Integer> batchPercentage) {
            $.batchPercentage = batchPercentage;
            return this;
        }

        /**
         * @param batchPercentage (Updatable) The percentage that will be used to determine how many instances will be deployed concurrently.
         * 
         * @return builder
         * 
         */
        public Builder batchPercentage(Integer batchPercentage) {
            return batchPercentage(Output.of(batchPercentage));
        }

        /**
         * @param policyType (Updatable) The type of policy used for rolling out a deployment stage.
         * 
         * @return builder
         * 
         */
        public Builder policyType(@Nullable Output<String> policyType) {
            $.policyType = policyType;
            return this;
        }

        /**
         * @param policyType (Updatable) The type of policy used for rolling out a deployment stage.
         * 
         * @return builder
         * 
         */
        public Builder policyType(String policyType) {
            return policyType(Output.of(policyType));
        }

        /**
         * @param rampLimitPercent (Updatable) Indicates the criteria to stop.
         * 
         * @return builder
         * 
         */
        public Builder rampLimitPercent(@Nullable Output<Double> rampLimitPercent) {
            $.rampLimitPercent = rampLimitPercent;
            return this;
        }

        /**
         * @param rampLimitPercent (Updatable) Indicates the criteria to stop.
         * 
         * @return builder
         * 
         */
        public Builder rampLimitPercent(Double rampLimitPercent) {
            return rampLimitPercent(Output.of(rampLimitPercent));
        }

        public DeployStageRolloutPolicyArgs build() {
            return $;
        }
    }

}