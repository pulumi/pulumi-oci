// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPolicyRequestProtectionRule;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPolicyRequestProtection {
    /**
     * @return References action by name from actions defined in WebAppFirewallPolicy. Executed if HTTP message body size exceeds limit set in field `bodyInspectionSizeLimitInBytes`.
     * 
     */
    private String bodyInspectionSizeLimitExceededActionName;
    /**
     * @return Maximum size of inspected HTTP message body in bytes. Actions to take if this limit is exceeded are defined in `bodyInspectionSizeLimitExceededActionName`.
     * 
     */
    private Integer bodyInspectionSizeLimitInBytes;
    /**
     * @return Ordered list of ProtectionRules. Rules are executed in order of appearance in this array. ProtectionRules in this array can only use protection capabilities of RESPONSE_PROTECTION_CAPABILITY type.
     * 
     */
    private List<GetWebAppFirewallPolicyRequestProtectionRule> rules;

    private GetWebAppFirewallPolicyRequestProtection() {}
    /**
     * @return References action by name from actions defined in WebAppFirewallPolicy. Executed if HTTP message body size exceeds limit set in field `bodyInspectionSizeLimitInBytes`.
     * 
     */
    public String bodyInspectionSizeLimitExceededActionName() {
        return this.bodyInspectionSizeLimitExceededActionName;
    }
    /**
     * @return Maximum size of inspected HTTP message body in bytes. Actions to take if this limit is exceeded are defined in `bodyInspectionSizeLimitExceededActionName`.
     * 
     */
    public Integer bodyInspectionSizeLimitInBytes() {
        return this.bodyInspectionSizeLimitInBytes;
    }
    /**
     * @return Ordered list of ProtectionRules. Rules are executed in order of appearance in this array. ProtectionRules in this array can only use protection capabilities of RESPONSE_PROTECTION_CAPABILITY type.
     * 
     */
    public List<GetWebAppFirewallPolicyRequestProtectionRule> rules() {
        return this.rules;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallPolicyRequestProtection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bodyInspectionSizeLimitExceededActionName;
        private Integer bodyInspectionSizeLimitInBytes;
        private List<GetWebAppFirewallPolicyRequestProtectionRule> rules;
        public Builder() {}
        public Builder(GetWebAppFirewallPolicyRequestProtection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bodyInspectionSizeLimitExceededActionName = defaults.bodyInspectionSizeLimitExceededActionName;
    	      this.bodyInspectionSizeLimitInBytes = defaults.bodyInspectionSizeLimitInBytes;
    	      this.rules = defaults.rules;
        }

        @CustomType.Setter
        public Builder bodyInspectionSizeLimitExceededActionName(String bodyInspectionSizeLimitExceededActionName) {
            this.bodyInspectionSizeLimitExceededActionName = Objects.requireNonNull(bodyInspectionSizeLimitExceededActionName);
            return this;
        }
        @CustomType.Setter
        public Builder bodyInspectionSizeLimitInBytes(Integer bodyInspectionSizeLimitInBytes) {
            this.bodyInspectionSizeLimitInBytes = Objects.requireNonNull(bodyInspectionSizeLimitInBytes);
            return this;
        }
        @CustomType.Setter
        public Builder rules(List<GetWebAppFirewallPolicyRequestProtectionRule> rules) {
            this.rules = Objects.requireNonNull(rules);
            return this;
        }
        public Builder rules(GetWebAppFirewallPolicyRequestProtectionRule... rules) {
            return rules(List.of(rules));
        }
        public GetWebAppFirewallPolicyRequestProtection build() {
            final var o = new GetWebAppFirewallPolicyRequestProtection();
            o.bodyInspectionSizeLimitExceededActionName = bodyInspectionSizeLimitExceededActionName;
            o.bodyInspectionSizeLimitInBytes = bodyInspectionSizeLimitInBytes;
            o.rules = rules;
            return o;
        }
    }
}