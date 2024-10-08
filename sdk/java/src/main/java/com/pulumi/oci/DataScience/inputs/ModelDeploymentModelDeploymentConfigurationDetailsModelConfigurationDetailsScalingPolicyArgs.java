// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.inputs.ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicyArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs Empty = new ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs();

    /**
     * (Updatable) The list of autoscaling policy details.
     * 
     */
    @Import(name="autoScalingPolicies")
    private @Nullable Output<List<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicyArgs>> autoScalingPolicies;

    /**
     * @return (Updatable) The list of autoscaling policy details.
     * 
     */
    public Optional<Output<List<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicyArgs>>> autoScalingPolicies() {
        return Optional.ofNullable(this.autoScalingPolicies);
    }

    /**
     * (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 600 seconds, which is also the default. The cooldown period starts when the model deployment becomes ACTIVE after the scaling operation.
     * 
     */
    @Import(name="coolDownInSeconds")
    private @Nullable Output<Integer> coolDownInSeconds;

    /**
     * @return (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 600 seconds, which is also the default. The cooldown period starts when the model deployment becomes ACTIVE after the scaling operation.
     * 
     */
    public Optional<Output<Integer>> coolDownInSeconds() {
        return Optional.ofNullable(this.coolDownInSeconds);
    }

    /**
     * (Updatable) The number of instances for the model deployment.
     * 
     */
    @Import(name="instanceCount")
    private @Nullable Output<Integer> instanceCount;

    /**
     * @return (Updatable) The number of instances for the model deployment.
     * 
     */
    public Optional<Output<Integer>> instanceCount() {
        return Optional.ofNullable(this.instanceCount);
    }

    /**
     * (Updatable) Whether the autoscaling policy is enabled.
     * 
     */
    @Import(name="isEnabled")
    private @Nullable Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Whether the autoscaling policy is enabled.
     * 
     */
    public Optional<Output<Boolean>> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    /**
     * (Updatable) The type of scaling policy.
     * 
     */
    @Import(name="policyType", required=true)
    private Output<String> policyType;

    /**
     * @return (Updatable) The type of scaling policy.
     * 
     */
    public Output<String> policyType() {
        return this.policyType;
    }

    private ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs() {}

    private ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs $) {
        this.autoScalingPolicies = $.autoScalingPolicies;
        this.coolDownInSeconds = $.coolDownInSeconds;
        this.instanceCount = $.instanceCount;
        this.isEnabled = $.isEnabled;
        this.policyType = $.policyType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs $;

        public Builder() {
            $ = new ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs();
        }

        public Builder(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs defaults) {
            $ = new ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autoScalingPolicies (Updatable) The list of autoscaling policy details.
         * 
         * @return builder
         * 
         */
        public Builder autoScalingPolicies(@Nullable Output<List<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicyArgs>> autoScalingPolicies) {
            $.autoScalingPolicies = autoScalingPolicies;
            return this;
        }

        /**
         * @param autoScalingPolicies (Updatable) The list of autoscaling policy details.
         * 
         * @return builder
         * 
         */
        public Builder autoScalingPolicies(List<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicyArgs> autoScalingPolicies) {
            return autoScalingPolicies(Output.of(autoScalingPolicies));
        }

        /**
         * @param autoScalingPolicies (Updatable) The list of autoscaling policy details.
         * 
         * @return builder
         * 
         */
        public Builder autoScalingPolicies(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicyArgs... autoScalingPolicies) {
            return autoScalingPolicies(List.of(autoScalingPolicies));
        }

        /**
         * @param coolDownInSeconds (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 600 seconds, which is also the default. The cooldown period starts when the model deployment becomes ACTIVE after the scaling operation.
         * 
         * @return builder
         * 
         */
        public Builder coolDownInSeconds(@Nullable Output<Integer> coolDownInSeconds) {
            $.coolDownInSeconds = coolDownInSeconds;
            return this;
        }

        /**
         * @param coolDownInSeconds (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 600 seconds, which is also the default. The cooldown period starts when the model deployment becomes ACTIVE after the scaling operation.
         * 
         * @return builder
         * 
         */
        public Builder coolDownInSeconds(Integer coolDownInSeconds) {
            return coolDownInSeconds(Output.of(coolDownInSeconds));
        }

        /**
         * @param instanceCount (Updatable) The number of instances for the model deployment.
         * 
         * @return builder
         * 
         */
        public Builder instanceCount(@Nullable Output<Integer> instanceCount) {
            $.instanceCount = instanceCount;
            return this;
        }

        /**
         * @param instanceCount (Updatable) The number of instances for the model deployment.
         * 
         * @return builder
         * 
         */
        public Builder instanceCount(Integer instanceCount) {
            return instanceCount(Output.of(instanceCount));
        }

        /**
         * @param isEnabled (Updatable) Whether the autoscaling policy is enabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(@Nullable Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Whether the autoscaling policy is enabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param policyType (Updatable) The type of scaling policy.
         * 
         * @return builder
         * 
         */
        public Builder policyType(Output<String> policyType) {
            $.policyType = policyType;
            return this;
        }

        /**
         * @param policyType (Updatable) The type of scaling policy.
         * 
         * @return builder
         * 
         */
        public Builder policyType(String policyType) {
            return policyType(Output.of(policyType));
        }

        public ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs build() {
            if ($.policyType == null) {
                throw new MissingRequiredPropertyException("ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs", "policyType");
            }
            return $;
        }
    }

}
