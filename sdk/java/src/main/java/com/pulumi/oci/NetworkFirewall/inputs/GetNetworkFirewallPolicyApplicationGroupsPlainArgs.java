// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.NetworkFirewall.inputs.GetNetworkFirewallPolicyApplicationGroupsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNetworkFirewallPolicyApplicationGroupsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallPolicyApplicationGroupsPlainArgs Empty = new GetNetworkFirewallPolicyApplicationGroupsPlainArgs();

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetNetworkFirewallPolicyApplicationGroupsFilter> filters;

    public Optional<List<GetNetworkFirewallPolicyApplicationGroupsFilter>> filters() {
        return Optional.ofNullable(this.filters);
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

    private GetNetworkFirewallPolicyApplicationGroupsPlainArgs() {}

    private GetNetworkFirewallPolicyApplicationGroupsPlainArgs(GetNetworkFirewallPolicyApplicationGroupsPlainArgs $) {
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallPolicyApplicationGroupsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallPolicyApplicationGroupsPlainArgs $;

        public Builder() {
            $ = new GetNetworkFirewallPolicyApplicationGroupsPlainArgs();
        }

        public Builder(GetNetworkFirewallPolicyApplicationGroupsPlainArgs defaults) {
            $ = new GetNetworkFirewallPolicyApplicationGroupsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetNetworkFirewallPolicyApplicationGroupsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetNetworkFirewallPolicyApplicationGroupsFilter... filters) {
            return filters(List.of(filters));
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

        public GetNetworkFirewallPolicyApplicationGroupsPlainArgs build() {
            $.networkFirewallPolicyId = Objects.requireNonNull($.networkFirewallPolicyId, "expected parameter 'networkFirewallPolicyId' to be non-null");
            return $;
        }
    }

}