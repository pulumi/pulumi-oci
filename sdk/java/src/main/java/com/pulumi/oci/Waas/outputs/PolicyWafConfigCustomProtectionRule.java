// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waas.outputs.PolicyWafConfigCustomProtectionRuleExclusion;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PolicyWafConfigCustomProtectionRule {
    /**
     * @return (Updatable) The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    private @Nullable String action;
    /**
     * @return (Updatable) An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     * 
     */
    private @Nullable List<PolicyWafConfigCustomProtectionRuleExclusion> exclusions;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom protection rule.
     * 
     */
    private @Nullable String id;

    private PolicyWafConfigCustomProtectionRule() {}
    /**
     * @return (Updatable) The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    public Optional<String> action() {
        return Optional.ofNullable(this.action);
    }
    /**
     * @return (Updatable) An array of The target property of a request that would allow it to bypass the protection rule. For example, when `target` is `REQUEST_COOKIE_NAMES`, the list may include names of cookies to exclude from the protection rule. When the target is `ARGS`, the list may include strings of URL query parameters and values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from the protection rule. `Exclusions` properties must not contain whitespace, comma or |. **Note:** If protection rules have been enabled that utilize the `maxArgumentCount` or `maxTotalNameLengthOfArguments` properties, and the `target` property has been set to `ARGS`, it is important that the `exclusions` properties be defined to honor those protection rule settings in a consistent manner.
     * 
     */
    public List<PolicyWafConfigCustomProtectionRuleExclusion> exclusions() {
        return this.exclusions == null ? List.of() : this.exclusions;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the custom protection rule.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PolicyWafConfigCustomProtectionRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String action;
        private @Nullable List<PolicyWafConfigCustomProtectionRuleExclusion> exclusions;
        private @Nullable String id;
        public Builder() {}
        public Builder(PolicyWafConfigCustomProtectionRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.exclusions = defaults.exclusions;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder action(@Nullable String action) {
            this.action = action;
            return this;
        }
        @CustomType.Setter
        public Builder exclusions(@Nullable List<PolicyWafConfigCustomProtectionRuleExclusion> exclusions) {
            this.exclusions = exclusions;
            return this;
        }
        public Builder exclusions(PolicyWafConfigCustomProtectionRuleExclusion... exclusions) {
            return exclusions(List.of(exclusions));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public PolicyWafConfigCustomProtectionRule build() {
            final var o = new PolicyWafConfigCustomProtectionRule();
            o.action = action;
            o.exclusions = exclusions;
            o.id = id;
            return o;
        }
    }
}