// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkFirewallPolicyMappedSecretPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallPolicyMappedSecretPlainArgs Empty = new GetNetworkFirewallPolicyMappedSecretPlainArgs();

    /**
     * Name of the secret.
     * 
     */
    @Import(name="name", required=true)
    private String name;

    /**
     * @return Name of the secret.
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

    private GetNetworkFirewallPolicyMappedSecretPlainArgs() {}

    private GetNetworkFirewallPolicyMappedSecretPlainArgs(GetNetworkFirewallPolicyMappedSecretPlainArgs $) {
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallPolicyMappedSecretPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallPolicyMappedSecretPlainArgs $;

        public Builder() {
            $ = new GetNetworkFirewallPolicyMappedSecretPlainArgs();
        }

        public Builder(GetNetworkFirewallPolicyMappedSecretPlainArgs defaults) {
            $ = new GetNetworkFirewallPolicyMappedSecretPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Name of the secret.
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

        public GetNetworkFirewallPolicyMappedSecretPlainArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            $.networkFirewallPolicyId = Objects.requireNonNull($.networkFirewallPolicyId, "expected parameter 'networkFirewallPolicyId' to be non-null");
            return $;
        }
    }

}