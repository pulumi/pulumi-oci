// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class AppFirewallPolicyResponseProtectionRuleProtectionCapabilityExclusions {
    /**
     * @return (Updatable) List of URL query parameter values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from inspecting. Example: If we have query parameter &#39;argumentName=argumentValue&#39; and args=[&#39;argumentName&#39;], both &#39;argumentName&#39; and &#39;argumentValue&#39; will not be inspected.
     * 
     */
    private @Nullable List<String> args;
    /**
     * @return (Updatable) List of HTTP request cookie values (by cookie name) to exclude from inspecting. Example: If we have cookie &#39;cookieName=cookieValue&#39; and requestCookies=[&#39;cookieName&#39;], both &#39;cookieName&#39; and &#39;cookieValue&#39; will not be inspected.
     * 
     */
    private @Nullable List<String> requestCookies;

    private AppFirewallPolicyResponseProtectionRuleProtectionCapabilityExclusions() {}
    /**
     * @return (Updatable) List of URL query parameter values from form-urlencoded XML, JSON, AMP, or POST payloads to exclude from inspecting. Example: If we have query parameter &#39;argumentName=argumentValue&#39; and args=[&#39;argumentName&#39;], both &#39;argumentName&#39; and &#39;argumentValue&#39; will not be inspected.
     * 
     */
    public List<String> args() {
        return this.args == null ? List.of() : this.args;
    }
    /**
     * @return (Updatable) List of HTTP request cookie values (by cookie name) to exclude from inspecting. Example: If we have cookie &#39;cookieName=cookieValue&#39; and requestCookies=[&#39;cookieName&#39;], both &#39;cookieName&#39; and &#39;cookieValue&#39; will not be inspected.
     * 
     */
    public List<String> requestCookies() {
        return this.requestCookies == null ? List.of() : this.requestCookies;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AppFirewallPolicyResponseProtectionRuleProtectionCapabilityExclusions defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> args;
        private @Nullable List<String> requestCookies;
        public Builder() {}
        public Builder(AppFirewallPolicyResponseProtectionRuleProtectionCapabilityExclusions defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.args = defaults.args;
    	      this.requestCookies = defaults.requestCookies;
        }

        @CustomType.Setter
        public Builder args(@Nullable List<String> args) {
            this.args = args;
            return this;
        }
        public Builder args(String... args) {
            return args(List.of(args));
        }
        @CustomType.Setter
        public Builder requestCookies(@Nullable List<String> requestCookies) {
            this.requestCookies = requestCookies;
            return this;
        }
        public Builder requestCookies(String... requestCookies) {
            return requestCookies(List.of(requestCookies));
        }
        public AppFirewallPolicyResponseProtectionRuleProtectionCapabilityExclusions build() {
            final var o = new AppFirewallPolicyResponseProtectionRuleProtectionCapabilityExclusions();
            o.args = args;
            o.requestCookies = requestCookies;
            return o;
        }
    }
}