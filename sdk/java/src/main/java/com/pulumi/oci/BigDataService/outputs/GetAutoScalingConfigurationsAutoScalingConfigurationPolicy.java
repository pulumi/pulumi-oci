// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.BigDataService.outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRule;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationsAutoScalingConfigurationPolicy {
    private String policyType;
    private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRule> rules;

    private GetAutoScalingConfigurationsAutoScalingConfigurationPolicy() {}
    public String policyType() {
        return this.policyType;
    }
    public List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRule> rules() {
        return this.rules;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String policyType;
        private List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRule> rules;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationsAutoScalingConfigurationPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.policyType = defaults.policyType;
    	      this.rules = defaults.rules;
        }

        @CustomType.Setter
        public Builder policyType(String policyType) {
            this.policyType = Objects.requireNonNull(policyType);
            return this;
        }
        @CustomType.Setter
        public Builder rules(List<GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRule> rules) {
            this.rules = Objects.requireNonNull(rules);
            return this;
        }
        public Builder rules(GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRule... rules) {
            return rules(List.of(rules));
        }
        public GetAutoScalingConfigurationsAutoScalingConfigurationPolicy build() {
            final var o = new GetAutoScalingConfigurationsAutoScalingConfigurationPolicy();
            o.policyType = policyType;
            o.rules = rules;
            return o;
        }
    }
}