// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkFirewallPolicyDecryptionProfilePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallPolicyDecryptionProfilePlainArgs Empty = new GetNetworkFirewallPolicyDecryptionProfilePlainArgs();

    /**
     * Unique Name of the decryption profile.
     * 
     */
    @Import(name="name", required=true)
    private String name;

    /**
     * @return Unique Name of the decryption profile.
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

    private GetNetworkFirewallPolicyDecryptionProfilePlainArgs() {}

    private GetNetworkFirewallPolicyDecryptionProfilePlainArgs(GetNetworkFirewallPolicyDecryptionProfilePlainArgs $) {
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallPolicyDecryptionProfilePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallPolicyDecryptionProfilePlainArgs $;

        public Builder() {
            $ = new GetNetworkFirewallPolicyDecryptionProfilePlainArgs();
        }

        public Builder(GetNetworkFirewallPolicyDecryptionProfilePlainArgs defaults) {
            $ = new GetNetworkFirewallPolicyDecryptionProfilePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Unique Name of the decryption profile.
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

        public GetNetworkFirewallPolicyDecryptionProfilePlainArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            $.networkFirewallPolicyId = Objects.requireNonNull($.networkFirewallPolicyId, "expected parameter 'networkFirewallPolicyId' to be non-null");
            return $;
        }
    }

}