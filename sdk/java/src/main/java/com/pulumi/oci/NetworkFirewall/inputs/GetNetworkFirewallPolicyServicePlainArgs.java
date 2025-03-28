// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkFirewallPolicyServicePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallPolicyServicePlainArgs Empty = new GetNetworkFirewallPolicyServicePlainArgs();

    /**
     * Name of the service.
     * 
     */
    @Import(name="name", required=true)
    private String name;

    /**
     * @return Name of the service.
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

    private GetNetworkFirewallPolicyServicePlainArgs() {}

    private GetNetworkFirewallPolicyServicePlainArgs(GetNetworkFirewallPolicyServicePlainArgs $) {
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallPolicyServicePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallPolicyServicePlainArgs $;

        public Builder() {
            $ = new GetNetworkFirewallPolicyServicePlainArgs();
        }

        public Builder(GetNetworkFirewallPolicyServicePlainArgs defaults) {
            $ = new GetNetworkFirewallPolicyServicePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Name of the service.
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

        public GetNetworkFirewallPolicyServicePlainArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyServicePlainArgs", "name");
            }
            if ($.networkFirewallPolicyId == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyServicePlainArgs", "networkFirewallPolicyId");
            }
            return $;
        }
    }

}
