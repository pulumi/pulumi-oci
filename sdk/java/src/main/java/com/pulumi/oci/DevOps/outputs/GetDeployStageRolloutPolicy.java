// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeployStageRolloutPolicy {
    /**
     * @return The number that will be used to determine how many instances will be deployed concurrently.
     * 
     */
    private Integer batchCount;
    /**
     * @return The duration of delay between batch rollout. The default delay is 1 minute.
     * 
     */
    private Integer batchDelayInSeconds;
    /**
     * @return The percentage that will be used to determine how many instances will be deployed concurrently.
     * 
     */
    private Integer batchPercentage;
    /**
     * @return The type of policy used for rolling out a deployment stage.
     * 
     */
    private String policyType;
    /**
     * @return Indicates the criteria to stop.
     * 
     */
    private Double rampLimitPercent;

    private GetDeployStageRolloutPolicy() {}
    /**
     * @return The number that will be used to determine how many instances will be deployed concurrently.
     * 
     */
    public Integer batchCount() {
        return this.batchCount;
    }
    /**
     * @return The duration of delay between batch rollout. The default delay is 1 minute.
     * 
     */
    public Integer batchDelayInSeconds() {
        return this.batchDelayInSeconds;
    }
    /**
     * @return The percentage that will be used to determine how many instances will be deployed concurrently.
     * 
     */
    public Integer batchPercentage() {
        return this.batchPercentage;
    }
    /**
     * @return The type of policy used for rolling out a deployment stage.
     * 
     */
    public String policyType() {
        return this.policyType;
    }
    /**
     * @return Indicates the criteria to stop.
     * 
     */
    public Double rampLimitPercent() {
        return this.rampLimitPercent;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployStageRolloutPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer batchCount;
        private Integer batchDelayInSeconds;
        private Integer batchPercentage;
        private String policyType;
        private Double rampLimitPercent;
        public Builder() {}
        public Builder(GetDeployStageRolloutPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.batchCount = defaults.batchCount;
    	      this.batchDelayInSeconds = defaults.batchDelayInSeconds;
    	      this.batchPercentage = defaults.batchPercentage;
    	      this.policyType = defaults.policyType;
    	      this.rampLimitPercent = defaults.rampLimitPercent;
        }

        @CustomType.Setter
        public Builder batchCount(Integer batchCount) {
            this.batchCount = Objects.requireNonNull(batchCount);
            return this;
        }
        @CustomType.Setter
        public Builder batchDelayInSeconds(Integer batchDelayInSeconds) {
            this.batchDelayInSeconds = Objects.requireNonNull(batchDelayInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder batchPercentage(Integer batchPercentage) {
            this.batchPercentage = Objects.requireNonNull(batchPercentage);
            return this;
        }
        @CustomType.Setter
        public Builder policyType(String policyType) {
            this.policyType = Objects.requireNonNull(policyType);
            return this;
        }
        @CustomType.Setter
        public Builder rampLimitPercent(Double rampLimitPercent) {
            this.rampLimitPercent = Objects.requireNonNull(rampLimitPercent);
            return this;
        }
        public GetDeployStageRolloutPolicy build() {
            final var o = new GetDeployStageRolloutPolicy();
            o.batchCount = batchCount;
            o.batchDelayInSeconds = batchDelayInSeconds;
            o.batchPercentage = batchPercentage;
            o.policyType = policyType;
            o.rampLimitPercent = rampLimitPercent;
            return o;
        }
    }
}