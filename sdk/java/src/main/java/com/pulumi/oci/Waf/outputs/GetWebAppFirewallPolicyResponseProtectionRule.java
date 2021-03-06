// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapability;
import com.pulumi.oci.Waf.outputs.GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapabilitySetting;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWebAppFirewallPolicyResponseProtectionRule {
    /**
     * @return Override action to take if capability was triggered, defined in Protection Rule for this capability. Only actions of type CHECK are allowed.
     * 
     */
    private final String actionName;
    /**
     * @return An expression that determines whether or not the rule action should be executed.
     * 
     */
    private final String condition;
    /**
     * @return The language used to parse condition from field `condition`. Available languages:
     * * **JMESPATH** an extended JMESPath language syntax.
     * 
     */
    private final String conditionLanguage;
    /**
     * @return Rule name. Must be unique within the module.
     * 
     */
    private final String name;
    /**
     * @return An ordered list that references OCI-managed protection capabilities. Referenced protection capabilities are executed in order of appearance. The array cannot contain entries with the same pair of capability key and version more than once.
     * 
     */
    private final List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapability> protectionCapabilities;
    /**
     * @return Settings for protection capabilities
     * 
     */
    private final List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapabilitySetting> protectionCapabilitySettings;
    /**
     * @return Type of WebAppFirewallPolicyRule.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GetWebAppFirewallPolicyResponseProtectionRule(
        @CustomType.Parameter("actionName") String actionName,
        @CustomType.Parameter("condition") String condition,
        @CustomType.Parameter("conditionLanguage") String conditionLanguage,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("protectionCapabilities") List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapability> protectionCapabilities,
        @CustomType.Parameter("protectionCapabilitySettings") List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapabilitySetting> protectionCapabilitySettings,
        @CustomType.Parameter("type") String type) {
        this.actionName = actionName;
        this.condition = condition;
        this.conditionLanguage = conditionLanguage;
        this.name = name;
        this.protectionCapabilities = protectionCapabilities;
        this.protectionCapabilitySettings = protectionCapabilitySettings;
        this.type = type;
    }

    /**
     * @return Override action to take if capability was triggered, defined in Protection Rule for this capability. Only actions of type CHECK are allowed.
     * 
     */
    public String actionName() {
        return this.actionName;
    }
    /**
     * @return An expression that determines whether or not the rule action should be executed.
     * 
     */
    public String condition() {
        return this.condition;
    }
    /**
     * @return The language used to parse condition from field `condition`. Available languages:
     * * **JMESPATH** an extended JMESPath language syntax.
     * 
     */
    public String conditionLanguage() {
        return this.conditionLanguage;
    }
    /**
     * @return Rule name. Must be unique within the module.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return An ordered list that references OCI-managed protection capabilities. Referenced protection capabilities are executed in order of appearance. The array cannot contain entries with the same pair of capability key and version more than once.
     * 
     */
    public List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapability> protectionCapabilities() {
        return this.protectionCapabilities;
    }
    /**
     * @return Settings for protection capabilities
     * 
     */
    public List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapabilitySetting> protectionCapabilitySettings() {
        return this.protectionCapabilitySettings;
    }
    /**
     * @return Type of WebAppFirewallPolicyRule.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWebAppFirewallPolicyResponseProtectionRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String actionName;
        private String condition;
        private String conditionLanguage;
        private String name;
        private List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapability> protectionCapabilities;
        private List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapabilitySetting> protectionCapabilitySettings;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWebAppFirewallPolicyResponseProtectionRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actionName = defaults.actionName;
    	      this.condition = defaults.condition;
    	      this.conditionLanguage = defaults.conditionLanguage;
    	      this.name = defaults.name;
    	      this.protectionCapabilities = defaults.protectionCapabilities;
    	      this.protectionCapabilitySettings = defaults.protectionCapabilitySettings;
    	      this.type = defaults.type;
        }

        public Builder actionName(String actionName) {
            this.actionName = Objects.requireNonNull(actionName);
            return this;
        }
        public Builder condition(String condition) {
            this.condition = Objects.requireNonNull(condition);
            return this;
        }
        public Builder conditionLanguage(String conditionLanguage) {
            this.conditionLanguage = Objects.requireNonNull(conditionLanguage);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder protectionCapabilities(List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapability> protectionCapabilities) {
            this.protectionCapabilities = Objects.requireNonNull(protectionCapabilities);
            return this;
        }
        public Builder protectionCapabilities(GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapability... protectionCapabilities) {
            return protectionCapabilities(List.of(protectionCapabilities));
        }
        public Builder protectionCapabilitySettings(List<GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapabilitySetting> protectionCapabilitySettings) {
            this.protectionCapabilitySettings = Objects.requireNonNull(protectionCapabilitySettings);
            return this;
        }
        public Builder protectionCapabilitySettings(GetWebAppFirewallPolicyResponseProtectionRuleProtectionCapabilitySetting... protectionCapabilitySettings) {
            return protectionCapabilitySettings(List.of(protectionCapabilitySettings));
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GetWebAppFirewallPolicyResponseProtectionRule build() {
            return new GetWebAppFirewallPolicyResponseProtectionRule(actionName, condition, conditionLanguage, name, protectionCapabilities, protectionCapabilitySettings, type);
        }
    }
}
