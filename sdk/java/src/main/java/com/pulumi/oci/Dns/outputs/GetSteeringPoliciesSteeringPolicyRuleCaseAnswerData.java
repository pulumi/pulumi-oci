// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData {
    /**
     * @return An expression that is used to select a set of answers that match a condition. For example, answers with matching pool properties.
     * 
     */
    private String answerCondition;
    /**
     * @return Keeps the answer only if the value is `true`.
     * 
     */
    private Boolean shouldKeep;
    /**
     * @return The rank assigned to the set of answers that match the expression in `answerCondition`. Answers with the lowest values move to the beginning of the list without changing the relative order of those with the same value. Answers can be given a value between `0` and `255`.
     * 
     */
    private Integer value;

    private GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData() {}
    /**
     * @return An expression that is used to select a set of answers that match a condition. For example, answers with matching pool properties.
     * 
     */
    public String answerCondition() {
        return this.answerCondition;
    }
    /**
     * @return Keeps the answer only if the value is `true`.
     * 
     */
    public Boolean shouldKeep() {
        return this.shouldKeep;
    }
    /**
     * @return The rank assigned to the set of answers that match the expression in `answerCondition`. Answers with the lowest values move to the beginning of the list without changing the relative order of those with the same value. Answers can be given a value between `0` and `255`.
     * 
     */
    public Integer value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String answerCondition;
        private Boolean shouldKeep;
        private Integer value;
        public Builder() {}
        public Builder(GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.answerCondition = defaults.answerCondition;
    	      this.shouldKeep = defaults.shouldKeep;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder answerCondition(String answerCondition) {
            if (answerCondition == null) {
              throw new MissingRequiredPropertyException("GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData", "answerCondition");
            }
            this.answerCondition = answerCondition;
            return this;
        }
        @CustomType.Setter
        public Builder shouldKeep(Boolean shouldKeep) {
            if (shouldKeep == null) {
              throw new MissingRequiredPropertyException("GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData", "shouldKeep");
            }
            this.shouldKeep = shouldKeep;
            return this;
        }
        @CustomType.Setter
        public Builder value(Integer value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData", "value");
            }
            this.value = value;
            return this;
        }
        public GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData build() {
            final var _resultValue = new GetSteeringPoliciesSteeringPolicyRuleCaseAnswerData();
            _resultValue.answerCondition = answerCondition;
            _resultValue.shouldKeep = shouldKeep;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
