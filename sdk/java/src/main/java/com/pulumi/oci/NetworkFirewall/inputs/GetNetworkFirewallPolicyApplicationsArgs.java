// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.NetworkFirewall.inputs.GetNetworkFirewallPolicyApplicationsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNetworkFirewallPolicyApplicationsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallPolicyApplicationsArgs Empty = new GetNetworkFirewallPolicyApplicationsArgs();

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetNetworkFirewallPolicyApplicationsFilterArgs>> filters;

    public Optional<Output<List<GetNetworkFirewallPolicyApplicationsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
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

    private GetNetworkFirewallPolicyApplicationsArgs() {}

    private GetNetworkFirewallPolicyApplicationsArgs(GetNetworkFirewallPolicyApplicationsArgs $) {
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallPolicyApplicationsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallPolicyApplicationsArgs $;

        public Builder() {
            $ = new GetNetworkFirewallPolicyApplicationsArgs();
        }

        public Builder(GetNetworkFirewallPolicyApplicationsArgs defaults) {
            $ = new GetNetworkFirewallPolicyApplicationsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetNetworkFirewallPolicyApplicationsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetNetworkFirewallPolicyApplicationsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetNetworkFirewallPolicyApplicationsFilterArgs... filters) {
            return filters(List.of(filters));
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

        public GetNetworkFirewallPolicyApplicationsArgs build() {
            $.networkFirewallPolicyId = Objects.requireNonNull($.networkFirewallPolicyId, "expected parameter 'networkFirewallPolicyId' to be non-null");
            return $;
        }
    }

}