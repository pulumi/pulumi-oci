// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waf.outputs.AppFirewallPolicyRequestProtectionRuleProtectionCapability;
import com.pulumi.oci.Waf.outputs.AppFirewallPolicyRequestProtectionRuleProtectionCapabilitySettings;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AppFirewallPolicyRequestProtectionRule {
    /**
     * @return (Updatable) Override action to take if capability was triggered, defined in Protection Rule for this capability. Only actions of type CHECK are allowed.
     * 
     */
    private final String actionName;
    /**
     * @return (Updatable) An expression that determines whether or not the rule action should be executed.
     * 
     */
    private final @Nullable String condition;
    /**
     * @return (Updatable) The language used to parse condition from field `condition`. Available languages:
     * * **JMESPATH** an extended JMESPath language syntax.
     * 
     */
    private final @Nullable String conditionLanguage;
    /**
     * @return (Updatable) Rule name. Must be unique within the module.
     * 
     */
    private final String name;
    /**
     * @return (Updatable) An ordered list that references OCI-managed protection capabilities. Referenced protection capabilities are executed in order of appearance. The array cannot contain entries with the same pair of capability key and version more than once.
     * 
     */
    private final List<AppFirewallPolicyRequestProtectionRuleProtectionCapability> protectionCapabilities;
    /**
     * @return (Updatable) Settings for protection capabilities
     * 
     */
    private final @Nullable AppFirewallPolicyRequestProtectionRuleProtectionCapabilitySettings protectionCapabilitySettings;
    /**
     * @return (Updatable) Type of WebAppFirewallPolicyRule.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private AppFirewallPolicyRequestProtectionRule(
        @CustomType.Parameter("actionName") String actionName,
        @CustomType.Parameter("condition") @Nullable String condition,
        @CustomType.Parameter("conditionLanguage") @Nullable String conditionLanguage,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("protectionCapabilities") List<AppFirewallPolicyRequestProtectionRuleProtectionCapability> protectionCapabilities,
        @CustomType.Parameter("protectionCapabilitySettings") @Nullable AppFirewallPolicyRequestProtectionRuleProtectionCapabilitySettings protectionCapabilitySettings,
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
     * @return (Updatable) Override action to take if capability was triggered, defined in Protection Rule for this capability. Only actions of type CHECK are allowed.
     * 
     */
    public String actionName() {
        return this.actionName;
    }
    /**
     * @return (Updatable) An expression that determines whether or not the rule action should be executed.
     * 
     */
    public Optional<String> condition() {
        return Optional.ofNullable(this.condition);
    }
    /**
     * @return (Updatable) The language used to parse condition from field `condition`. Available languages:
     * * **JMESPATH** an extended JMESPath language syntax.
     * 
     */
    public Optional<String> conditionLanguage() {
        return Optional.ofNullable(this.conditionLanguage);
    }
    /**
     * @return (Updatable) Rule name. Must be unique within the module.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return (Updatable) An ordered list that references OCI-managed protection capabilities. Referenced protection capabilities are executed in order of appearance. The array cannot contain entries with the same pair of capability key and version more than once.
     * 
     */
    public List<AppFirewallPolicyRequestProtectionRuleProtectionCapability> protectionCapabilities() {
        return this.protectionCapabilities;
    }
    /**
     * @return (Updatable) Settings for protection capabilities
     * 
     */
    public Optional<AppFirewallPolicyRequestProtectionRuleProtectionCapabilitySettings> protectionCapabilitySettings() {
        return Optional.ofNullable(this.protectionCapabilitySettings);
    }
    /**
     * @return (Updatable) Type of WebAppFirewallPolicyRule.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AppFirewallPolicyRequestProtectionRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String actionName;
        private @Nullable String condition;
        private @Nullable String conditionLanguage;
        private String name;
        private List<AppFirewallPolicyRequestProtectionRuleProtectionCapability> protectionCapabilities;
        private @Nullable AppFirewallPolicyRequestProtectionRuleProtectionCapabilitySettings protectionCapabilitySettings;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(AppFirewallPolicyRequestProtectionRule defaults) {
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
        public Builder condition(@Nullable String condition) {
            this.condition = condition;
            return this;
        }
        public Builder conditionLanguage(@Nullable String conditionLanguage) {
            this.conditionLanguage = conditionLanguage;
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder protectionCapabilities(List<AppFirewallPolicyRequestProtectionRuleProtectionCapability> protectionCapabilities) {
            this.protectionCapabilities = Objects.requireNonNull(protectionCapabilities);
            return this;
        }
        public Builder protectionCapabilities(AppFirewallPolicyRequestProtectionRuleProtectionCapability... protectionCapabilities) {
            return protectionCapabilities(List.of(protectionCapabilities));
        }
        public Builder protectionCapabilitySettings(@Nullable AppFirewallPolicyRequestProtectionRuleProtectionCapabilitySettings protectionCapabilitySettings) {
            this.protectionCapabilitySettings = protectionCapabilitySettings;
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public AppFirewallPolicyRequestProtectionRule build() {
            return new AppFirewallPolicyRequestProtectionRule(actionName, condition, conditionLanguage, name, protectionCapabilities, protectionCapabilitySettings, type);
        }
    }
}
