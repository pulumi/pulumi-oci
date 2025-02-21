// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkFirewall.inputs.GetNetworkFirewallsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNetworkFirewallsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNetworkFirewallsPlainArgs Empty = new GetNetworkFirewallsPlainArgs();

    /**
     * A filter to return only resources that are present within the specified availability domain. To get a list of availability domains for a tenancy, use [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable String availabilityDomain;

    /**
     * @return A filter to return only resources that are present within the specified availability domain. To get a list of availability domains for a tenancy, use [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

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
    private @Nullable List<GetNetworkFirewallsFilter> filters;

    public Optional<List<GetNetworkFirewallsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall resource.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall resource.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources that match the entire networkFirewallPolicyId given.
     * 
     */
    @Import(name="networkFirewallPolicyId")
    private @Nullable String networkFirewallPolicyId;

    /**
     * @return A filter to return only resources that match the entire networkFirewallPolicyId given.
     * 
     */
    public Optional<String> networkFirewallPolicyId() {
        return Optional.ofNullable(this.networkFirewallPolicyId);
    }

    /**
     * A filter to return only resources with a lifecycleState matching the given value.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources with a lifecycleState matching the given value.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetNetworkFirewallsPlainArgs() {}

    private GetNetworkFirewallsPlainArgs(GetNetworkFirewallsPlainArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNetworkFirewallsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNetworkFirewallsPlainArgs $;

        public Builder() {
            $ = new GetNetworkFirewallsPlainArgs();
        }

        public Builder(GetNetworkFirewallsPlainArgs defaults) {
            $ = new GetNetworkFirewallsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain A filter to return only resources that are present within the specified availability domain. To get a list of availability domains for a tenancy, use [ListAvailabilityDomains](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/AvailabilityDomain/ListAvailabilityDomains) operation. Example: `kIdk:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
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

        public Builder filters(@Nullable List<GetNetworkFirewallsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetNetworkFirewallsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Network Firewall resource.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param networkFirewallPolicyId A filter to return only resources that match the entire networkFirewallPolicyId given.
         * 
         * @return builder
         * 
         */
        public Builder networkFirewallPolicyId(@Nullable String networkFirewallPolicyId) {
            $.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }

        /**
         * @param state A filter to return only resources with a lifecycleState matching the given value.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetNetworkFirewallsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetNetworkFirewallsPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
