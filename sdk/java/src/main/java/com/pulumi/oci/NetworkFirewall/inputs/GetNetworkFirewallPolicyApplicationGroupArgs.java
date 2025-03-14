// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetNetworkFirewallPolicyApplicationGroupArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallPolicyApplicationGroupArgs Empty = new GetNetworkFirewallPolicyApplicationGroupArgs();

    /**
     * Name of the application Group.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return Name of the application Group.
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

    private GetNetworkFirewallPolicyApplicationGroupArgs() {}

    private GetNetworkFirewallPolicyApplicationGroupArgs(GetNetworkFirewallPolicyApplicationGroupArgs $) {
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallPolicyApplicationGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallPolicyApplicationGroupArgs $;

        public Builder() {
            $ = new GetNetworkFirewallPolicyApplicationGroupArgs();
        }

        public Builder(GetNetworkFirewallPolicyApplicationGroupArgs defaults) {
            $ = new GetNetworkFirewallPolicyApplicationGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Name of the application Group.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name of the application Group.
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

        public GetNetworkFirewallPolicyApplicationGroupArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyApplicationGroupArgs", "name");
            }
            if ($.networkFirewallPolicyId == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyApplicationGroupArgs", "networkFirewallPolicyId");
            }
            return $;
        }
    }

}
