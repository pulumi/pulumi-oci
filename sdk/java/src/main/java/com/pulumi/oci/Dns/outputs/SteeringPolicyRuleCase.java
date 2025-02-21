// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Dns.outputs.SteeringPolicyRuleCaseAnswerData;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class SteeringPolicyRuleCase {
    /**
     * @return An array of `SteeringPolicyPriorityAnswerData` objects.
     * 
     */
    private @Nullable List<SteeringPolicyRuleCaseAnswerData> answerDatas;
    /**
     * @return An expression that uses conditions at the time of a DNS query to indicate whether a case matches. Conditions may include the geographical location, IP subnet, or ASN the DNS query originated. **Example:** If you have an office that uses the subnet `192.0.2.0/24` you could use a `caseCondition` expression `query.client.address in (&#39;192.0.2.0/24&#39;)` to define a case that matches queries from that office.
     * 
     */
    private @Nullable String caseCondition;
    /**
     * @return The number of answers allowed to remain after the limit rule has been processed, keeping only the first of the remaining answers in the list. Example: If the `count` property is set to `2` and four answers remain before the limit rule is processed, only the first two answers in the list will remain after the limit rule has been processed.
     * 
     */
    private @Nullable Integer count;

    private SteeringPolicyRuleCase() {}
    /**
     * @return An array of `SteeringPolicyPriorityAnswerData` objects.
     * 
     */
    public List<SteeringPolicyRuleCaseAnswerData> answerDatas() {
        return this.answerDatas == null ? List.of() : this.answerDatas;
    }
    /**
     * @return An expression that uses conditions at the time of a DNS query to indicate whether a case matches. Conditions may include the geographical location, IP subnet, or ASN the DNS query originated. **Example:** If you have an office that uses the subnet `192.0.2.0/24` you could use a `caseCondition` expression `query.client.address in (&#39;192.0.2.0/24&#39;)` to define a case that matches queries from that office.
     * 
     */
    public Optional<String> caseCondition() {
        return Optional.ofNullable(this.caseCondition);
    }
    /**
     * @return The number of answers allowed to remain after the limit rule has been processed, keeping only the first of the remaining answers in the list. Example: If the `count` property is set to `2` and four answers remain before the limit rule is processed, only the first two answers in the list will remain after the limit rule has been processed.
     * 
     */
    public Optional<Integer> count() {
        return Optional.ofNullable(this.count);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(SteeringPolicyRuleCase defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<SteeringPolicyRuleCaseAnswerData> answerDatas;
        private @Nullable String caseCondition;
        private @Nullable Integer count;
        public Builder() {}
        public Builder(SteeringPolicyRuleCase defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.answerDatas = defaults.answerDatas;
    	      this.caseCondition = defaults.caseCondition;
    	      this.count = defaults.count;
        }

        @CustomType.Setter
        public Builder answerDatas(@Nullable List<SteeringPolicyRuleCaseAnswerData> answerDatas) {

            this.answerDatas = answerDatas;
            return this;
        }
        public Builder answerDatas(SteeringPolicyRuleCaseAnswerData... answerDatas) {
            return answerDatas(List.of(answerDatas));
        }
        @CustomType.Setter
        public Builder caseCondition(@Nullable String caseCondition) {

            this.caseCondition = caseCondition;
            return this;
        }
        @CustomType.Setter
        public Builder count(@Nullable Integer count) {

            this.count = count;
            return this;
        }
        public SteeringPolicyRuleCase build() {
            final var _resultValue = new SteeringPolicyRuleCase();
            _resultValue.answerDatas = answerDatas;
            _resultValue.caseCondition = caseCondition;
            _resultValue.count = count;
            return _resultValue;
        }
    }
}
