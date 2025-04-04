// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicy;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicy {
    /**
     * @return (Updatable) The list of autoscaling policy details.
     * 
     */
    private @Nullable List<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicy> autoScalingPolicies;
    /**
     * @return (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 600 seconds, which is also the default. The cooldown period starts when the model deployment becomes ACTIVE after the scaling operation.
     * 
     */
    private @Nullable Integer coolDownInSeconds;
    /**
     * @return (Updatable) The number of instances for the model deployment.
     * 
     */
    private @Nullable Integer instanceCount;
    /**
     * @return (Updatable) Whether the autoscaling policy is enabled.
     * 
     */
    private @Nullable Boolean isEnabled;
    /**
     * @return (Updatable) The type of scaling policy.
     * 
     */
    private String policyType;

    private ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicy() {}
    /**
     * @return (Updatable) The list of autoscaling policy details.
     * 
     */
    public List<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicy> autoScalingPolicies() {
        return this.autoScalingPolicies == null ? List.of() : this.autoScalingPolicies;
    }
    /**
     * @return (Updatable) For threshold-based autoscaling policies, this value is the minimum period of time to wait between scaling actions. The cooldown period gives the system time to stabilize before rescaling. The minimum value is 600 seconds, which is also the default. The cooldown period starts when the model deployment becomes ACTIVE after the scaling operation.
     * 
     */
    public Optional<Integer> coolDownInSeconds() {
        return Optional.ofNullable(this.coolDownInSeconds);
    }
    /**
     * @return (Updatable) The number of instances for the model deployment.
     * 
     */
    public Optional<Integer> instanceCount() {
        return Optional.ofNullable(this.instanceCount);
    }
    /**
     * @return (Updatable) Whether the autoscaling policy is enabled.
     * 
     */
    public Optional<Boolean> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }
    /**
     * @return (Updatable) The type of scaling policy.
     * 
     */
    public String policyType() {
        return this.policyType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicy> autoScalingPolicies;
        private @Nullable Integer coolDownInSeconds;
        private @Nullable Integer instanceCount;
        private @Nullable Boolean isEnabled;
        private String policyType;
        public Builder() {}
        public Builder(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autoScalingPolicies = defaults.autoScalingPolicies;
    	      this.coolDownInSeconds = defaults.coolDownInSeconds;
    	      this.instanceCount = defaults.instanceCount;
    	      this.isEnabled = defaults.isEnabled;
    	      this.policyType = defaults.policyType;
        }

        @CustomType.Setter
        public Builder autoScalingPolicies(@Nullable List<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicy> autoScalingPolicies) {

            this.autoScalingPolicies = autoScalingPolicies;
            return this;
        }
        public Builder autoScalingPolicies(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyAutoScalingPolicy... autoScalingPolicies) {
            return autoScalingPolicies(List.of(autoScalingPolicies));
        }
        @CustomType.Setter
        public Builder coolDownInSeconds(@Nullable Integer coolDownInSeconds) {

            this.coolDownInSeconds = coolDownInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder instanceCount(@Nullable Integer instanceCount) {

            this.instanceCount = instanceCount;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(@Nullable Boolean isEnabled) {

            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder policyType(String policyType) {
            if (policyType == null) {
              throw new MissingRequiredPropertyException("ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicy", "policyType");
            }
            this.policyType = policyType;
            return this;
        }
        public ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicy build() {
            final var _resultValue = new ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicy();
            _resultValue.autoScalingPolicies = autoScalingPolicies;
            _resultValue.coolDownInSeconds = coolDownInSeconds;
            _resultValue.instanceCount = instanceCount;
            _resultValue.isEnabled = isEnabled;
            _resultValue.policyType = policyType;
            return _resultValue;
        }
    }
}
