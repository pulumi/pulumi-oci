// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waas.outputs.GetProtectionRulesProtectionRuleExclusion;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetProtectionRulesProtectionRule {
    /**
     * @return Filter rules using a list of actions.
     * 
     */
    private String action;
    /**
     * @return The description of the protection rule.
     * 
     */
    private String description;
    /**
     * @return An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     * 
     */
    private List<GetProtectionRulesProtectionRuleExclusion> exclusions;
    /**
     * @return The unique key of the protection rule.
     * 
     */
    private String key;
    /**
     * @return The list of labels for the protection rule.
     * 
     */
    private List<String> labels;
    /**
     * @return The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity&#39;s open source WAF rules, see [Mod Security&#39;s documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
     * 
     */
    private List<String> modSecurityRuleIds;
    /**
     * @return The name of the protection rule.
     * 
     */
    private String name;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     * 
     */
    private String waasPolicyId;

    private GetProtectionRulesProtectionRule() {}
    /**
     * @return Filter rules using a list of actions.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return The description of the protection rule.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     * 
     */
    public List<GetProtectionRulesProtectionRuleExclusion> exclusions() {
        return this.exclusions;
    }
    /**
     * @return The unique key of the protection rule.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The list of labels for the protection rule.
     * 
     */
    public List<String> labels() {
        return this.labels;
    }
    /**
     * @return The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity&#39;s open source WAF rules, see [Mod Security&#39;s documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
     * 
     */
    public List<String> modSecurityRuleIds() {
        return this.modSecurityRuleIds;
    }
    /**
     * @return The name of the protection rule.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     * 
     */
    public String waasPolicyId() {
        return this.waasPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProtectionRulesProtectionRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private String description;
        private List<GetProtectionRulesProtectionRuleExclusion> exclusions;
        private String key;
        private List<String> labels;
        private List<String> modSecurityRuleIds;
        private String name;
        private String waasPolicyId;
        public Builder() {}
        public Builder(GetProtectionRulesProtectionRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.description = defaults.description;
    	      this.exclusions = defaults.exclusions;
    	      this.key = defaults.key;
    	      this.labels = defaults.labels;
    	      this.modSecurityRuleIds = defaults.modSecurityRuleIds;
    	      this.name = defaults.name;
    	      this.waasPolicyId = defaults.waasPolicyId;
        }

        @CustomType.Setter
        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder exclusions(List<GetProtectionRulesProtectionRuleExclusion> exclusions) {
            this.exclusions = Objects.requireNonNull(exclusions);
            return this;
        }
        public Builder exclusions(GetProtectionRulesProtectionRuleExclusion... exclusions) {
            return exclusions(List.of(exclusions));
        }
        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        @CustomType.Setter
        public Builder labels(List<String> labels) {
            this.labels = Objects.requireNonNull(labels);
            return this;
        }
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }
        @CustomType.Setter
        public Builder modSecurityRuleIds(List<String> modSecurityRuleIds) {
            this.modSecurityRuleIds = Objects.requireNonNull(modSecurityRuleIds);
            return this;
        }
        public Builder modSecurityRuleIds(String... modSecurityRuleIds) {
            return modSecurityRuleIds(List.of(modSecurityRuleIds));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder waasPolicyId(String waasPolicyId) {
            this.waasPolicyId = Objects.requireNonNull(waasPolicyId);
            return this;
        }
        public GetProtectionRulesProtectionRule build() {
            final var o = new GetProtectionRulesProtectionRule();
            o.action = action;
            o.description = description;
            o.exclusions = exclusions;
            o.key = key;
            o.labels = labels;
            o.modSecurityRuleIds = modSecurityRuleIds;
            o.name = name;
            o.waasPolicyId = waasPolicyId;
            return o;
        }
    }
}