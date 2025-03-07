// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkFirewallPolicySecurityRulePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallPolicySecurityRulePlainArgs Empty = new GetNetworkFirewallPolicySecurityRulePlainArgs();

    /**
     * Name for the Security rule, must be unique within the policy.
     * 
     */
    @Import(name="name", required=true)
    private String name;

    /**
     * @return Name for the Security rule, must be unique within the policy.
     * 
     */
    public String name() {
        return this.name;
    }

    /**
     * Unique Network Firewall Policy identifier
     * 
     */
    @Import(name="networkFirewallPolicyId", required=true)
    private String networkFirewallPolicyId;

    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public String networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }

    private GetNetworkFirewallPolicySecurityRulePlainArgs() {}

    private GetNetworkFirewallPolicySecurityRulePlainArgs(GetNetworkFirewallPolicySecurityRulePlainArgs $) {
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallPolicySecurityRulePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallPolicySecurityRulePlainArgs $;

        public Builder() {
            $ = new GetNetworkFirewallPolicySecurityRulePlainArgs();
        }

        public Builder(GetNetworkFirewallPolicySecurityRulePlainArgs defaults) {
            $ = new GetNetworkFirewallPolicySecurityRulePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Name for the Security rule, must be unique within the policy.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            $.name = name;
            return this;
        }

        /**
         * @param networkFirewallPolicyId Unique Network Firewall Policy identifier
         * 
         * @return builder
         * 
         */
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            $.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }

        public GetNetworkFirewallPolicySecurityRulePlainArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRulePlainArgs", "name");
            }
            if ($.networkFirewallPolicyId == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallPolicySecurityRulePlainArgs", "networkFirewallPolicyId");
            }
            return $;
        }
    }

}
