// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseTools.inputs.DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DatabaseToolsPrivateEndpointState extends com.pulumi.resources.ResourceArgs {

    public static final DatabaseToolsPrivateEndpointState Empty = new DatabaseToolsPrivateEndpointState();

    /**
     * A list of additional FQDNs that can be also be used for the private endpoint.
     * 
     */
    @Import(name="additionalFqdns")
    private @Nullable Output<List<String>> additionalFqdns;

    /**
     * @return A list of additional FQDNs that can be also be used for the private endpoint.
     * 
     */
    public Optional<Output<List<String>>> additionalFqdns() {
        return Optional.ofNullable(this.additionalFqdns);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A description of the Database Tools private endpoint.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A description of the Database Tools private endpoint.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Then FQDN to use for the private endpoint.
     * 
     */
    @Import(name="endpointFqdn")
    private @Nullable Output<String> endpointFqdn;

    /**
     * @return Then FQDN to use for the private endpoint.
     * 
     */
    public Optional<Output<String>> endpointFqdn() {
        return Optional.ofNullable(this.endpointFqdn);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
     * 
     */
    @Import(name="endpointServiceId")
    private @Nullable Output<String> endpointServiceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
     * 
     */
    public Optional<Output<String>> endpointServiceId() {
        return Optional.ofNullable(this.endpointServiceId);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint&#39;s VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
     * 
     */
    @Import(name="nsgIds")
    private @Nullable Output<List<String>> nsgIds;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint&#39;s VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
     * 
     */
    public Optional<Output<List<String>>> nsgIds() {
        return Optional.ofNullable(this.nsgIds);
    }

    /**
     * The private IP address that represents the access point for the associated endpoint service.
     * 
     */
    @Import(name="privateEndpointIp")
    private @Nullable Output<String> privateEndpointIp;

    /**
     * @return The private IP address that represents the access point for the associated endpoint service.
     * 
     */
    public Optional<Output<String>> privateEndpointIp() {
        return Optional.ofNullable(this.privateEndpointIp);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint&#39;s VNIC.
     * 
     */
    @Import(name="privateEndpointVnicId")
    private @Nullable Output<String> privateEndpointVnicId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint&#39;s VNIC.
     * 
     */
    public Optional<Output<String>> privateEndpointVnicId() {
        return Optional.ofNullable(this.privateEndpointVnicId);
    }

    /**
     * Reverse connection configuration details of the private endpoint.
     * 
     */
    @Import(name="reverseConnectionConfigurations")
    private @Nullable Output<List<DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgs>> reverseConnectionConfigurations;

    /**
     * @return Reverse connection configuration details of the private endpoint.
     * 
     */
    public Optional<Output<List<DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgs>>> reverseConnectionConfigurations() {
        return Optional.ofNullable(this.reverseConnectionConfigurations);
    }

    /**
     * The current state of the Database Tools private endpoint.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Database Tools private endpoint.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
     * 
     */
    @Import(name="subnetId")
    private @Nullable Output<String> subnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
     * 
     */
    public Optional<Output<String>> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,Object>> systemTags;

    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time the Database Tools private endpoint was created. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the Database Tools private endpoint was created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the Database Tools private endpoint was updated. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the Database Tools private endpoint was updated. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN that the private endpoint belongs to.
     * 
     */
    @Import(name="vcnId")
    private @Nullable Output<String> vcnId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN that the private endpoint belongs to.
     * 
     */
    public Optional<Output<String>> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private DatabaseToolsPrivateEndpointState() {}

    private DatabaseToolsPrivateEndpointState(DatabaseToolsPrivateEndpointState $) {
        this.additionalFqdns = $.additionalFqdns;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.endpointFqdn = $.endpointFqdn;
        this.endpointServiceId = $.endpointServiceId;
        this.freeformTags = $.freeformTags;
        this.lifecycleDetails = $.lifecycleDetails;
        this.nsgIds = $.nsgIds;
        this.privateEndpointIp = $.privateEndpointIp;
        this.privateEndpointVnicId = $.privateEndpointVnicId;
        this.reverseConnectionConfigurations = $.reverseConnectionConfigurations;
        this.state = $.state;
        this.subnetId = $.subnetId;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatabaseToolsPrivateEndpointState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatabaseToolsPrivateEndpointState $;

        public Builder() {
            $ = new DatabaseToolsPrivateEndpointState();
        }

        public Builder(DatabaseToolsPrivateEndpointState defaults) {
            $ = new DatabaseToolsPrivateEndpointState(Objects.requireNonNull(defaults));
        }

        /**
         * @param additionalFqdns A list of additional FQDNs that can be also be used for the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder additionalFqdns(@Nullable Output<List<String>> additionalFqdns) {
            $.additionalFqdns = additionalFqdns;
            return this;
        }

        /**
         * @param additionalFqdns A list of additional FQDNs that can be also be used for the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder additionalFqdns(List<String> additionalFqdns) {
            return additionalFqdns(Output.of(additionalFqdns));
        }

        /**
         * @param additionalFqdns A list of additional FQDNs that can be also be used for the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder additionalFqdns(String... additionalFqdns) {
            return additionalFqdns(List.of(additionalFqdns));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A description of the Database Tools private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A description of the Database Tools private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param endpointFqdn Then FQDN to use for the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder endpointFqdn(@Nullable Output<String> endpointFqdn) {
            $.endpointFqdn = endpointFqdn;
            return this;
        }

        /**
         * @param endpointFqdn Then FQDN to use for the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder endpointFqdn(String endpointFqdn) {
            return endpointFqdn(Output.of(endpointFqdn));
        }

        /**
         * @param endpointServiceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
         * 
         * @return builder
         * 
         */
        public Builder endpointServiceId(@Nullable Output<String> endpointServiceId) {
            $.endpointServiceId = endpointServiceId;
            return this;
        }

        /**
         * @param endpointServiceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
         * 
         * @return builder
         * 
         */
        public Builder endpointServiceId(String endpointServiceId) {
            return endpointServiceId(Output.of(endpointServiceId));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param nsgIds (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint&#39;s VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(@Nullable Output<List<String>> nsgIds) {
            $.nsgIds = nsgIds;
            return this;
        }

        /**
         * @param nsgIds (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint&#39;s VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(List<String> nsgIds) {
            return nsgIds(Output.of(nsgIds));
        }

        /**
         * @param nsgIds (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint&#39;s VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
         * 
         * @return builder
         * 
         */
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }

        /**
         * @param privateEndpointIp The private IP address that represents the access point for the associated endpoint service.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointIp(@Nullable Output<String> privateEndpointIp) {
            $.privateEndpointIp = privateEndpointIp;
            return this;
        }

        /**
         * @param privateEndpointIp The private IP address that represents the access point for the associated endpoint service.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointIp(String privateEndpointIp) {
            return privateEndpointIp(Output.of(privateEndpointIp));
        }

        /**
         * @param privateEndpointVnicId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint&#39;s VNIC.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointVnicId(@Nullable Output<String> privateEndpointVnicId) {
            $.privateEndpointVnicId = privateEndpointVnicId;
            return this;
        }

        /**
         * @param privateEndpointVnicId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint&#39;s VNIC.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointVnicId(String privateEndpointVnicId) {
            return privateEndpointVnicId(Output.of(privateEndpointVnicId));
        }

        /**
         * @param reverseConnectionConfigurations Reverse connection configuration details of the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder reverseConnectionConfigurations(@Nullable Output<List<DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgs>> reverseConnectionConfigurations) {
            $.reverseConnectionConfigurations = reverseConnectionConfigurations;
            return this;
        }

        /**
         * @param reverseConnectionConfigurations Reverse connection configuration details of the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder reverseConnectionConfigurations(List<DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgs> reverseConnectionConfigurations) {
            return reverseConnectionConfigurations(Output.of(reverseConnectionConfigurations));
        }

        /**
         * @param reverseConnectionConfigurations Reverse connection configuration details of the private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder reverseConnectionConfigurations(DatabaseToolsPrivateEndpointReverseConnectionConfigurationArgs... reverseConnectionConfigurations) {
            return reverseConnectionConfigurations(List.of(reverseConnectionConfigurations));
        }

        /**
         * @param state The current state of the Database Tools private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Database Tools private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param subnetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(@Nullable Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,Object>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,Object> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time the Database Tools private endpoint was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the Database Tools private endpoint was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the Database Tools private endpoint was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the Database Tools private endpoint was updated. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param vcnId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN that the private endpoint belongs to.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN that the private endpoint belongs to.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public DatabaseToolsPrivateEndpointState build() {
            return $;
        }
    }

}