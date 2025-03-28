// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRuleExclusion;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule {
    /**
     * @return The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    private String action;
    /**
     * @return An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     * 
     */
    private List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRuleExclusion> exclusions;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom protection rule.
     * 
     */
    private String id;

    private GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule() {}
    /**
     * @return The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRuleExclusion> exclusions() {
        return this.exclusions;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom protection rule.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRuleExclusion> exclusions;
        private String id;
        public Builder() {}
        public Builder(GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.exclusions = defaults.exclusions;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder action(String action) {
            if (action == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule", "action");
            }
            this.action = action;
            return this;
        }
        @CustomType.Setter
        public Builder exclusions(List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRuleExclusion> exclusions) {
            if (exclusions == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule", "exclusions");
            }
            this.exclusions = exclusions;
            return this;
        }
        public Builder exclusions(GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRuleExclusion... exclusions) {
            return exclusions(List.of(exclusions));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule", "id");
            }
            this.id = id;
            return this;
        }
        public GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule build() {
            final var _resultValue = new GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule();
            _resultValue.action = action;
            _resultValue.exclusions = exclusions;
            _resultValue.id = id;
            return _resultValue;
        }
    }
}
