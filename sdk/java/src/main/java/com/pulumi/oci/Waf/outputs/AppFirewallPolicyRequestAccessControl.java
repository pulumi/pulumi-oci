// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waf.outputs.AppFirewallPolicyRequestAccessControlRule;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class AppFirewallPolicyRequestAccessControl {
    /**
     * @return (Updatable) References an default Action to take if no AccessControlRule was matched. Allowed action types:
     * * **ALLOW** continues execution of other modules and their rules.
     * * **RETURN_HTTP_RESPONSE** terminates further execution of modules and rules and returns defined HTTP response.
     * 
     */
    private String defaultActionName;
    /**
     * @return (Updatable) Ordered list of ProtectionRules. Rules are executed in order of appearance in this array. ProtectionRules in this array can only use protection capabilities of RESPONSE_PROTECTION_CAPABILITY type.
     * 
     */
    private @Nullable List<AppFirewallPolicyRequestAccessControlRule> rules;

    private AppFirewallPolicyRequestAccessControl() {}
    /**
     * @return (Updatable) References an default Action to take if no AccessControlRule was matched. Allowed action types:
     * * **ALLOW** continues execution of other modules and their rules.
     * * **RETURN_HTTP_RESPONSE** terminates further execution of modules and rules and returns defined HTTP response.
     * 
     */
    public String defaultActionName() {
        return this.defaultActionName;
    }
    /**
     * @return (Updatable) Ordered list of ProtectionRules. Rules are executed in order of appearance in this array. ProtectionRules in this array can only use protection capabilities of RESPONSE_PROTECTION_CAPABILITY type.
     * 
     */
    public List<AppFirewallPolicyRequestAccessControlRule> rules() {
        return this.rules == null ? List.of() : this.rules;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AppFirewallPolicyRequestAccessControl defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String defaultActionName;
        private @Nullable List<AppFirewallPolicyRequestAccessControlRule> rules;
        public Builder() {}
        public Builder(AppFirewallPolicyRequestAccessControl defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.defaultActionName = defaults.defaultActionName;
    	      this.rules = defaults.rules;
        }

        @CustomType.Setter
        public Builder defaultActionName(String defaultActionName) {
            this.defaultActionName = Objects.requireNonNull(defaultActionName);
            return this;
        }
        @CustomType.Setter
        public Builder rules(@Nullable List<AppFirewallPolicyRequestAccessControlRule> rules) {
            this.rules = rules;
            return this;
        }
        public Builder rules(AppFirewallPolicyRequestAccessControlRule... rules) {
            return rules(List.of(rules));
        }
        public AppFirewallPolicyRequestAccessControl build() {
            final var o = new AppFirewallPolicyRequestAccessControl();
            o.defaultActionName = defaultActionName;
            o.rules = rules;
            return o;
        }
    }
}