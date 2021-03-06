// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigAccessRule;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigAddressRateLimiting;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigCachingRule;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigCaptcha;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallenge;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigJsChallenge;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigProtectionSetting;
import com.pulumi.oci.Waas.outputs.GetWaasPoliciesWaasPolicyWafConfigWhitelist;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWaasPoliciesWaasPolicyWafConfig {
    /**
     * @return The access rules applied to the Web Application Firewall. Used for defining custom access policies with the combination of `ALLOW`, `DETECT`, and `BLOCK` rules, based on different criteria.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigAccessRule> accessRules;
    /**
     * @return The IP address rate limiting settings used to limit the number of requests from an address.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigAddressRateLimiting> addressRateLimitings;
    /**
     * @return A list of caching rules applied to the web application.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigCachingRule> cachingRules;
    /**
     * @return A list of CAPTCHA challenge settings. These are used to challenge requests with a CAPTCHA to block bots.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigCaptcha> captchas;
    /**
     * @return A list of the custom protection rule OCIDs and their actions.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule> customProtectionRules;
    /**
     * @return The device fingerprint challenge settings. Used to detect unique devices based on the device fingerprint information collected in order to block bots.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge> deviceFingerprintChallenges;
    /**
     * @return The human interaction challenge settings. Used to look for natural human interactions such as mouse movements, time on site, and page scrolling to identify bots.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallenge> humanInteractionChallenges;
    /**
     * @return The JavaScript challenge settings. Used to challenge requests with a JavaScript challenge and take the action if a browser has no JavaScript support in order to block bots.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigJsChallenge> jsChallenges;
    /**
     * @return The key in the map of origins referencing the origin used for the Web Application Firewall. The origin must already be included in `Origins`. Required when creating the `WafConfig` resource, but not on update.
     * 
     */
    private final String origin;
    /**
     * @return The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
     * 
     */
    private final List<String> originGroups;
    /**
     * @return The settings to apply to protection rules.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigProtectionSetting> protectionSettings;
    /**
     * @return A list of IP addresses that bypass the Web Application Firewall.
     * 
     */
    private final List<GetWaasPoliciesWaasPolicyWafConfigWhitelist> whitelists;

    @CustomType.Constructor
    private GetWaasPoliciesWaasPolicyWafConfig(
        @CustomType.Parameter("accessRules") List<GetWaasPoliciesWaasPolicyWafConfigAccessRule> accessRules,
        @CustomType.Parameter("addressRateLimitings") List<GetWaasPoliciesWaasPolicyWafConfigAddressRateLimiting> addressRateLimitings,
        @CustomType.Parameter("cachingRules") List<GetWaasPoliciesWaasPolicyWafConfigCachingRule> cachingRules,
        @CustomType.Parameter("captchas") List<GetWaasPoliciesWaasPolicyWafConfigCaptcha> captchas,
        @CustomType.Parameter("customProtectionRules") List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule> customProtectionRules,
        @CustomType.Parameter("deviceFingerprintChallenges") List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge> deviceFingerprintChallenges,
        @CustomType.Parameter("humanInteractionChallenges") List<GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallenge> humanInteractionChallenges,
        @CustomType.Parameter("jsChallenges") List<GetWaasPoliciesWaasPolicyWafConfigJsChallenge> jsChallenges,
        @CustomType.Parameter("origin") String origin,
        @CustomType.Parameter("originGroups") List<String> originGroups,
        @CustomType.Parameter("protectionSettings") List<GetWaasPoliciesWaasPolicyWafConfigProtectionSetting> protectionSettings,
        @CustomType.Parameter("whitelists") List<GetWaasPoliciesWaasPolicyWafConfigWhitelist> whitelists) {
        this.accessRules = accessRules;
        this.addressRateLimitings = addressRateLimitings;
        this.cachingRules = cachingRules;
        this.captchas = captchas;
        this.customProtectionRules = customProtectionRules;
        this.deviceFingerprintChallenges = deviceFingerprintChallenges;
        this.humanInteractionChallenges = humanInteractionChallenges;
        this.jsChallenges = jsChallenges;
        this.origin = origin;
        this.originGroups = originGroups;
        this.protectionSettings = protectionSettings;
        this.whitelists = whitelists;
    }

    /**
     * @return The access rules applied to the Web Application Firewall. Used for defining custom access policies with the combination of `ALLOW`, `DETECT`, and `BLOCK` rules, based on different criteria.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigAccessRule> accessRules() {
        return this.accessRules;
    }
    /**
     * @return The IP address rate limiting settings used to limit the number of requests from an address.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigAddressRateLimiting> addressRateLimitings() {
        return this.addressRateLimitings;
    }
    /**
     * @return A list of caching rules applied to the web application.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigCachingRule> cachingRules() {
        return this.cachingRules;
    }
    /**
     * @return A list of CAPTCHA challenge settings. These are used to challenge requests with a CAPTCHA to block bots.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigCaptcha> captchas() {
        return this.captchas;
    }
    /**
     * @return A list of the custom protection rule OCIDs and their actions.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule> customProtectionRules() {
        return this.customProtectionRules;
    }
    /**
     * @return The device fingerprint challenge settings. Used to detect unique devices based on the device fingerprint information collected in order to block bots.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge> deviceFingerprintChallenges() {
        return this.deviceFingerprintChallenges;
    }
    /**
     * @return The human interaction challenge settings. Used to look for natural human interactions such as mouse movements, time on site, and page scrolling to identify bots.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallenge> humanInteractionChallenges() {
        return this.humanInteractionChallenges;
    }
    /**
     * @return The JavaScript challenge settings. Used to challenge requests with a JavaScript challenge and take the action if a browser has no JavaScript support in order to block bots.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigJsChallenge> jsChallenges() {
        return this.jsChallenges;
    }
    /**
     * @return The key in the map of origins referencing the origin used for the Web Application Firewall. The origin must already be included in `Origins`. Required when creating the `WafConfig` resource, but not on update.
     * 
     */
    public String origin() {
        return this.origin;
    }
    /**
     * @return The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
     * 
     */
    public List<String> originGroups() {
        return this.originGroups;
    }
    /**
     * @return The settings to apply to protection rules.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigProtectionSetting> protectionSettings() {
        return this.protectionSettings;
    }
    /**
     * @return A list of IP addresses that bypass the Web Application Firewall.
     * 
     */
    public List<GetWaasPoliciesWaasPolicyWafConfigWhitelist> whitelists() {
        return this.whitelists;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWaasPoliciesWaasPolicyWafConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetWaasPoliciesWaasPolicyWafConfigAccessRule> accessRules;
        private List<GetWaasPoliciesWaasPolicyWafConfigAddressRateLimiting> addressRateLimitings;
        private List<GetWaasPoliciesWaasPolicyWafConfigCachingRule> cachingRules;
        private List<GetWaasPoliciesWaasPolicyWafConfigCaptcha> captchas;
        private List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule> customProtectionRules;
        private List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge> deviceFingerprintChallenges;
        private List<GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallenge> humanInteractionChallenges;
        private List<GetWaasPoliciesWaasPolicyWafConfigJsChallenge> jsChallenges;
        private String origin;
        private List<String> originGroups;
        private List<GetWaasPoliciesWaasPolicyWafConfigProtectionSetting> protectionSettings;
        private List<GetWaasPoliciesWaasPolicyWafConfigWhitelist> whitelists;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWaasPoliciesWaasPolicyWafConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessRules = defaults.accessRules;
    	      this.addressRateLimitings = defaults.addressRateLimitings;
    	      this.cachingRules = defaults.cachingRules;
    	      this.captchas = defaults.captchas;
    	      this.customProtectionRules = defaults.customProtectionRules;
    	      this.deviceFingerprintChallenges = defaults.deviceFingerprintChallenges;
    	      this.humanInteractionChallenges = defaults.humanInteractionChallenges;
    	      this.jsChallenges = defaults.jsChallenges;
    	      this.origin = defaults.origin;
    	      this.originGroups = defaults.originGroups;
    	      this.protectionSettings = defaults.protectionSettings;
    	      this.whitelists = defaults.whitelists;
        }

        public Builder accessRules(List<GetWaasPoliciesWaasPolicyWafConfigAccessRule> accessRules) {
            this.accessRules = Objects.requireNonNull(accessRules);
            return this;
        }
        public Builder accessRules(GetWaasPoliciesWaasPolicyWafConfigAccessRule... accessRules) {
            return accessRules(List.of(accessRules));
        }
        public Builder addressRateLimitings(List<GetWaasPoliciesWaasPolicyWafConfigAddressRateLimiting> addressRateLimitings) {
            this.addressRateLimitings = Objects.requireNonNull(addressRateLimitings);
            return this;
        }
        public Builder addressRateLimitings(GetWaasPoliciesWaasPolicyWafConfigAddressRateLimiting... addressRateLimitings) {
            return addressRateLimitings(List.of(addressRateLimitings));
        }
        public Builder cachingRules(List<GetWaasPoliciesWaasPolicyWafConfigCachingRule> cachingRules) {
            this.cachingRules = Objects.requireNonNull(cachingRules);
            return this;
        }
        public Builder cachingRules(GetWaasPoliciesWaasPolicyWafConfigCachingRule... cachingRules) {
            return cachingRules(List.of(cachingRules));
        }
        public Builder captchas(List<GetWaasPoliciesWaasPolicyWafConfigCaptcha> captchas) {
            this.captchas = Objects.requireNonNull(captchas);
            return this;
        }
        public Builder captchas(GetWaasPoliciesWaasPolicyWafConfigCaptcha... captchas) {
            return captchas(List.of(captchas));
        }
        public Builder customProtectionRules(List<GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule> customProtectionRules) {
            this.customProtectionRules = Objects.requireNonNull(customProtectionRules);
            return this;
        }
        public Builder customProtectionRules(GetWaasPoliciesWaasPolicyWafConfigCustomProtectionRule... customProtectionRules) {
            return customProtectionRules(List.of(customProtectionRules));
        }
        public Builder deviceFingerprintChallenges(List<GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge> deviceFingerprintChallenges) {
            this.deviceFingerprintChallenges = Objects.requireNonNull(deviceFingerprintChallenges);
            return this;
        }
        public Builder deviceFingerprintChallenges(GetWaasPoliciesWaasPolicyWafConfigDeviceFingerprintChallenge... deviceFingerprintChallenges) {
            return deviceFingerprintChallenges(List.of(deviceFingerprintChallenges));
        }
        public Builder humanInteractionChallenges(List<GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallenge> humanInteractionChallenges) {
            this.humanInteractionChallenges = Objects.requireNonNull(humanInteractionChallenges);
            return this;
        }
        public Builder humanInteractionChallenges(GetWaasPoliciesWaasPolicyWafConfigHumanInteractionChallenge... humanInteractionChallenges) {
            return humanInteractionChallenges(List.of(humanInteractionChallenges));
        }
        public Builder jsChallenges(List<GetWaasPoliciesWaasPolicyWafConfigJsChallenge> jsChallenges) {
            this.jsChallenges = Objects.requireNonNull(jsChallenges);
            return this;
        }
        public Builder jsChallenges(GetWaasPoliciesWaasPolicyWafConfigJsChallenge... jsChallenges) {
            return jsChallenges(List.of(jsChallenges));
        }
        public Builder origin(String origin) {
            this.origin = Objects.requireNonNull(origin);
            return this;
        }
        public Builder originGroups(List<String> originGroups) {
            this.originGroups = Objects.requireNonNull(originGroups);
            return this;
        }
        public Builder originGroups(String... originGroups) {
            return originGroups(List.of(originGroups));
        }
        public Builder protectionSettings(List<GetWaasPoliciesWaasPolicyWafConfigProtectionSetting> protectionSettings) {
            this.protectionSettings = Objects.requireNonNull(protectionSettings);
            return this;
        }
        public Builder protectionSettings(GetWaasPoliciesWaasPolicyWafConfigProtectionSetting... protectionSettings) {
            return protectionSettings(List.of(protectionSettings));
        }
        public Builder whitelists(List<GetWaasPoliciesWaasPolicyWafConfigWhitelist> whitelists) {
            this.whitelists = Objects.requireNonNull(whitelists);
            return this;
        }
        public Builder whitelists(GetWaasPoliciesWaasPolicyWafConfigWhitelist... whitelists) {
            return whitelists(List.of(whitelists));
        }        public GetWaasPoliciesWaasPolicyWafConfig build() {
            return new GetWaasPoliciesWaasPolicyWafConfig(accessRules, addressRateLimitings, cachingRules, captchas, customProtectionRules, deviceFingerprintChallenges, humanInteractionChallenges, jsChallenges, origin, originGroups, protectionSettings, whitelists);
        }
    }
}
