// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkFirewallPolicySecurityRuleArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallPolicySecurityRuleArgs Empty = new GetNetworkFirewallPolicySecurityRuleArgs();

    /**
     * Name for the Security rule, must be unique within the policy.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return Name for the Security rule, must be unique within the policy.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * Unique Network Firewall Policy identifier
     * 
     */
    @Import(name="networkFirewallPolicyId", required=true)
    private Output<String> networkFirewallPolicyId;

    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public Output<String> networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }

    private GetNetworkFirewallPolicySecurityRuleArgs() {}

    private GetNetworkFirewallPolicySecurityRuleArgs(GetNetworkFirewallPolicySecurityRuleArgs $) {
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallPolicySecurityRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallPolicySecurityRuleArgs $;

        public Builder() {
            $ = new GetNetworkFirewallPolicySecurityRuleArgs();
        }

        public Builder(GetNetworkFirewallPolicySecurityRuleArgs defaults) {
            $ = new GetNetworkFirewallPolicySecurityRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Name for the Security rule, must be unique within the policy.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name for the Security rule, must be unique within the policy.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param networkFirewallPolicyId Unique Network Firewall Policy identifier
         * 
         * @return builder
         * 
         */
        public Builder networkFirewallPolicyId(Output<String> networkFirewallPolicyId) {
            $.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }

        /**
         * @param networkFirewallPolicyId Unique Network Firewall Policy identifier
         * 
         * @return builder
         * 
         */
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            return networkFirewallPolicyId(Output.of(networkFirewallPolicyId));
        }

        public GetNetworkFirewallPolicySecurityRuleArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleArgs", "name");
            }
            if ($.networkFirewallPolicyId == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRuleArgs", "networkFirewallPolicyId");
            }
            return $;
        }
    }

}
