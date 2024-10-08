// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeight {
    /**
     * @return (Updatable) Unique key of collaborative capability for which weight will be overridden.
     * 
     */
    private String key;
    /**
     * @return (Updatable) The value of weight to set.
     * 
     */
    private Integer weight;

    private AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeight() {}
    /**
     * @return (Updatable) Unique key of collaborative capability for which weight will be overridden.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return (Updatable) The value of weight to set.
     * 
     */
    public Integer weight() {
        return this.weight;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeight defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String key;
        private Integer weight;
        public Builder() {}
        public Builder(AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeight defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.weight = defaults.weight;
        }

        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeight", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder weight(Integer weight) {
            if (weight == null) {
              throw new MissingRequiredPropertyException("AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeight", "weight");
            }
            this.weight = weight;
            return this;
        }
        public AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeight build() {
            final var _resultValue = new AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeight();
            _resultValue.key = key;
            _resultValue.weight = weight;
            return _resultValue;
        }
    }
}
