// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkFirewallPolicySecurityRuleCondition {
    /**
     * @return An array of application list names to be evaluated against the traffic protocol and protocol-specific parameters.
     * 
     */
    private List<String> applications;
    /**
     * @return An array of IP address list names to be evaluated against the traffic destination address.
     * 
     */
    private List<String> destinationAddresses;
    /**
     * @return An array of service list names to be evaluated against the traffic protocol and protocol-specific parameters.
     * 
     */
    private List<String> services;
    /**
     * @return An array of IP address list names to be evaluated against the traffic source address.
     * 
     */
    private List<String> sourceAddresses;
    /**
     * @return An array of URL pattern list names to be evaluated against the HTTP(S) request target.
     * 
     */
    private List<String> urls;

    private GetNetworkFirewallPolicySecurityRuleCondition() {}
    /**
     * @return An array of application list names to be evaluated against the traffic protocol and protocol-specific parameters.
     * 
     */
    public List<String> applications() {
        return this.applications;
    }
    /**
     * @return An array of IP address list names to be evaluated against the traffic destination address.
     * 
     */
    public List<String> destinationAddresses() {
        return this.destinationAddresses;
    }
    /**
     * @return An array of service list names to be evaluated against the traffic protocol and protocol-specific parameters.
     * 
     */
    public List<String> services() {
        return this.services;
    }
    /**
     * @return An array of IP address list names to be evaluated against the traffic source address.
     * 
     */
    public List<String> sourceAddresses() {
        return this.sourceAddresses;
    }
    /**
     * @return An array of URL pattern list names to be evaluated against the HTTP(S) request target.
     * 
     */
    public List<String> urls() {
        return this.urls;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicySecurityRuleCondition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> applications;
        private List<String> destinationAddresses;
        private List<String> services;
        private List<String> sourceAddresses;
        private List<String> urls;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicySecurityRuleCondition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applications = defaults.applications;
    	      this.destinationAddresses = defaults.destinationAddresses;
    	      this.services = defaults.services;
    	      this.sourceAddresses = defaults.sourceAddresses;
    	      this.urls = defaults.urls;
        }

        @CustomType.Setter
        public Builder applications(List<String> applications) {
            if (applications == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleCondition", "applications");
            }
            this.applications = applications;
            return this;
        }
        public Builder applications(String... applications) {
            return applications(List.of(applications));
        }
        @CustomType.Setter
        public Builder destinationAddresses(List<String> destinationAddresses) {
            if (destinationAddresses == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleCondition", "destinationAddresses");
            }
            this.destinationAddresses = destinationAddresses;
            return this;
        }
        public Builder destinationAddresses(String... destinationAddresses) {
            return destinationAddresses(List.of(destinationAddresses));
        }
        @CustomType.Setter
        public Builder services(List<String> services) {
            if (services == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleCondition", "services");
            }
            this.services = services;
            return this;
        }
        public Builder services(String... services) {
            return services(List.of(services));
        }
        @CustomType.Setter
        public Builder sourceAddresses(List<String> sourceAddresses) {
            if (sourceAddresses == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleCondition", "sourceAddresses");
            }
            this.sourceAddresses = sourceAddresses;
            return this;
        }
        public Builder sourceAddresses(String... sourceAddresses) {
            return sourceAddresses(List.of(sourceAddresses));
        }
        @CustomType.Setter
        public Builder urls(List<String> urls) {
            if (urls == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleCondition", "urls");
            }
            this.urls = urls;
            return this;
        }
        public Builder urls(String... urls) {
            return urls(List.of(urls));
        }
        public GetNetworkFirewallPolicySecurityRuleCondition build() {
            final var _resultValue = new GetNetworkFirewallPolicySecurityRuleCondition();
            _resultValue.applications = applications;
            _resultValue.destinationAddresses = destinationAddresses;
            _resultValue.services = services;
            _resultValue.sourceAddresses = sourceAddresses;
            _resultValue.urls = urls;
            return _resultValue;
        }
    }
}
