// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceState extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceState Empty = new WorkspaceState();

    /**
     * (Updatable) The OCID of the compartment containing the workspace.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment containing the workspace.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user defined description for the workspace.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user defined description for the workspace.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The IP of the custom DNS.
     * 
     */
    @Import(name="dnsServerIp")
    private @Nullable Output<String> dnsServerIp;

    /**
     * @return The IP of the custom DNS.
     * 
     */
    public Optional<Output<String>> dnsServerIp() {
        return Optional.ofNullable(this.dnsServerIp);
    }

    /**
     * The DNS zone of the custom DNS to use to resolve names.
     * 
     */
    @Import(name="dnsServerZone")
    private @Nullable Output<String> dnsServerZone;

    /**
     * @return The DNS zone of the custom DNS to use to resolve names.
     * 
     */
    public Optional<Output<String>> dnsServerZone() {
        return Optional.ofNullable(this.dnsServerZone);
    }

    /**
     * DCMS PRivate Endpoint Compartment Identifier
     * 
     */
    @Import(name="endpointCompartmentId")
    private @Nullable Output<String> endpointCompartmentId;

    /**
     * @return DCMS PRivate Endpoint Compartment Identifier
     * 
     */
    public Optional<Output<String>> endpointCompartmentId() {
        return Optional.ofNullable(this.endpointCompartmentId);
    }

    /**
     * DCMS Private Endpoint ID associated with workspace if the pvt networking is enabled
     * 
     */
    @Import(name="endpointId")
    private @Nullable Output<String> endpointId;

    /**
     * @return DCMS Private Endpoint ID associated with workspace if the pvt networking is enabled
     * 
     */
    public Optional<Output<String>> endpointId() {
        return Optional.ofNullable(this.endpointId);
    }

    /**
     * DCMS Private Endpoint Name
     * 
     */
    @Import(name="endpointName")
    private @Nullable Output<String> endpointName;

    /**
     * @return DCMS Private Endpoint Name
     * 
     */
    public Optional<Output<String>> endpointName() {
        return Optional.ofNullable(this.endpointName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    @Import(name="isForceOperation")
    private @Nullable Output<Boolean> isForceOperation;

    public Optional<Output<Boolean>> isForceOperation() {
        return Optional.ofNullable(this.isForceOperation);
    }

    /**
     * Specifies whether the private network connection is enabled or disabled.
     * 
     */
    @Import(name="isPrivateNetworkEnabled")
    private @Nullable Output<Boolean> isPrivateNetworkEnabled;

    /**
     * @return Specifies whether the private network connection is enabled or disabled.
     * 
     */
    public Optional<Output<Boolean>> isPrivateNetworkEnabled() {
        return Optional.ofNullable(this.isPrivateNetworkEnabled);
    }

    @Import(name="quiesceTimeout")
    private @Nullable Output<Integer> quiesceTimeout;

    public Optional<Output<Integer>> quiesceTimeout() {
        return Optional.ofNullable(this.quiesceTimeout);
    }

    /**
     * DCMS Data Asset Registry Compartment Identifier
     * 
     */
    @Import(name="registryCompartmentId")
    private @Nullable Output<String> registryCompartmentId;

    /**
     * @return DCMS Data Asset Registry Compartment Identifier
     * 
     */
    public Optional<Output<String>> registryCompartmentId() {
        return Optional.ofNullable(this.registryCompartmentId);
    }

    /**
     * DCMS Data Asset Registry ID to which the workspace is associated
     * 
     */
    @Import(name="registryId")
    private @Nullable Output<String> registryId;

    /**
     * @return DCMS Data Asset Registry ID to which the workspace is associated
     * 
     */
    public Optional<Output<String>> registryId() {
        return Optional.ofNullable(this.registryId);
    }

    /**
     * DCMS Data Asset Registry display name
     * 
     */
    @Import(name="registryName")
    private @Nullable Output<String> registryName;

    /**
     * @return DCMS Data Asset Registry display name
     * 
     */
    public Optional<Output<String>> registryName() {
        return Optional.ofNullable(this.registryName);
    }

    /**
     * Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn&#39;t available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn&#39;t available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     * 
     */
    @Import(name="stateMessage")
    private @Nullable Output<String> stateMessage;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     * 
     */
    public Optional<Output<String>> stateMessage() {
        return Optional.ofNullable(this.stateMessage);
    }

    /**
     * The OCID of the subnet for customer connected databases.
     * 
     */
    @Import(name="subnetId")
    private @Nullable Output<String> subnetId;

    /**
     * @return The OCID of the subnet for customer connected databases.
     * 
     */
    public Optional<Output<String>> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    /**
     * The date and time the workspace was created, in the timestamp format defined by RFC3339.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the workspace was created, in the timestamp format defined by RFC3339.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * The OCID of the VCN the subnet is in.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="vcnId")
    private @Nullable Output<String> vcnId;

    /**
     * @return The OCID of the VCN the subnet is in.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private WorkspaceState() {}

    private WorkspaceState(WorkspaceState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.dnsServerIp = $.dnsServerIp;
        this.dnsServerZone = $.dnsServerZone;
        this.endpointCompartmentId = $.endpointCompartmentId;
        this.endpointId = $.endpointId;
        this.endpointName = $.endpointName;
        this.freeformTags = $.freeformTags;
        this.isForceOperation = $.isForceOperation;
        this.isPrivateNetworkEnabled = $.isPrivateNetworkEnabled;
        this.quiesceTimeout = $.quiesceTimeout;
        this.registryCompartmentId = $.registryCompartmentId;
        this.registryId = $.registryId;
        this.registryName = $.registryName;
        this.state = $.state;
        this.stateMessage = $.stateMessage;
        this.subnetId = $.subnetId;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceState $;

        public Builder() {
            $ = new WorkspaceState();
        }

        public Builder(WorkspaceState defaults) {
            $ = new WorkspaceState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing the workspace.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing the workspace.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A user defined description for the workspace.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user defined description for the workspace.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param dnsServerIp The IP of the custom DNS.
         * 
         * @return builder
         * 
         */
        public Builder dnsServerIp(@Nullable Output<String> dnsServerIp) {
            $.dnsServerIp = dnsServerIp;
            return this;
        }

        /**
         * @param dnsServerIp The IP of the custom DNS.
         * 
         * @return builder
         * 
         */
        public Builder dnsServerIp(String dnsServerIp) {
            return dnsServerIp(Output.of(dnsServerIp));
        }

        /**
         * @param dnsServerZone The DNS zone of the custom DNS to use to resolve names.
         * 
         * @return builder
         * 
         */
        public Builder dnsServerZone(@Nullable Output<String> dnsServerZone) {
            $.dnsServerZone = dnsServerZone;
            return this;
        }

        /**
         * @param dnsServerZone The DNS zone of the custom DNS to use to resolve names.
         * 
         * @return builder
         * 
         */
        public Builder dnsServerZone(String dnsServerZone) {
            return dnsServerZone(Output.of(dnsServerZone));
        }

        /**
         * @param endpointCompartmentId DCMS PRivate Endpoint Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder endpointCompartmentId(@Nullable Output<String> endpointCompartmentId) {
            $.endpointCompartmentId = endpointCompartmentId;
            return this;
        }

        /**
         * @param endpointCompartmentId DCMS PRivate Endpoint Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder endpointCompartmentId(String endpointCompartmentId) {
            return endpointCompartmentId(Output.of(endpointCompartmentId));
        }

        /**
         * @param endpointId DCMS Private Endpoint ID associated with workspace if the pvt networking is enabled
         * 
         * @return builder
         * 
         */
        public Builder endpointId(@Nullable Output<String> endpointId) {
            $.endpointId = endpointId;
            return this;
        }

        /**
         * @param endpointId DCMS Private Endpoint ID associated with workspace if the pvt networking is enabled
         * 
         * @return builder
         * 
         */
        public Builder endpointId(String endpointId) {
            return endpointId(Output.of(endpointId));
        }

        /**
         * @param endpointName DCMS Private Endpoint Name
         * 
         * @return builder
         * 
         */
        public Builder endpointName(@Nullable Output<String> endpointName) {
            $.endpointName = endpointName;
            return this;
        }

        /**
         * @param endpointName DCMS Private Endpoint Name
         * 
         * @return builder
         * 
         */
        public Builder endpointName(String endpointName) {
            return endpointName(Output.of(endpointName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        public Builder isForceOperation(@Nullable Output<Boolean> isForceOperation) {
            $.isForceOperation = isForceOperation;
            return this;
        }

        public Builder isForceOperation(Boolean isForceOperation) {
            return isForceOperation(Output.of(isForceOperation));
        }

        /**
         * @param isPrivateNetworkEnabled Specifies whether the private network connection is enabled or disabled.
         * 
         * @return builder
         * 
         */
        public Builder isPrivateNetworkEnabled(@Nullable Output<Boolean> isPrivateNetworkEnabled) {
            $.isPrivateNetworkEnabled = isPrivateNetworkEnabled;
            return this;
        }

        /**
         * @param isPrivateNetworkEnabled Specifies whether the private network connection is enabled or disabled.
         * 
         * @return builder
         * 
         */
        public Builder isPrivateNetworkEnabled(Boolean isPrivateNetworkEnabled) {
            return isPrivateNetworkEnabled(Output.of(isPrivateNetworkEnabled));
        }

        public Builder quiesceTimeout(@Nullable Output<Integer> quiesceTimeout) {
            $.quiesceTimeout = quiesceTimeout;
            return this;
        }

        public Builder quiesceTimeout(Integer quiesceTimeout) {
            return quiesceTimeout(Output.of(quiesceTimeout));
        }

        /**
         * @param registryCompartmentId DCMS Data Asset Registry Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder registryCompartmentId(@Nullable Output<String> registryCompartmentId) {
            $.registryCompartmentId = registryCompartmentId;
            return this;
        }

        /**
         * @param registryCompartmentId DCMS Data Asset Registry Compartment Identifier
         * 
         * @return builder
         * 
         */
        public Builder registryCompartmentId(String registryCompartmentId) {
            return registryCompartmentId(Output.of(registryCompartmentId));
        }

        /**
         * @param registryId DCMS Data Asset Registry ID to which the workspace is associated
         * 
         * @return builder
         * 
         */
        public Builder registryId(@Nullable Output<String> registryId) {
            $.registryId = registryId;
            return this;
        }

        /**
         * @param registryId DCMS Data Asset Registry ID to which the workspace is associated
         * 
         * @return builder
         * 
         */
        public Builder registryId(String registryId) {
            return registryId(Output.of(registryId));
        }

        /**
         * @param registryName DCMS Data Asset Registry display name
         * 
         * @return builder
         * 
         */
        public Builder registryName(@Nullable Output<String> registryName) {
            $.registryName = registryName;
            return this;
        }

        /**
         * @param registryName DCMS Data Asset Registry display name
         * 
         * @return builder
         * 
         */
        public Builder registryName(String registryName) {
            return registryName(Output.of(registryName));
        }

        /**
         * @param state Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn&#39;t available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn&#39;t available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param stateMessage A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
         * 
         * @return builder
         * 
         */
        public Builder stateMessage(@Nullable Output<String> stateMessage) {
            $.stateMessage = stateMessage;
            return this;
        }

        /**
         * @param stateMessage A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
         * 
         * @return builder
         * 
         */
        public Builder stateMessage(String stateMessage) {
            return stateMessage(Output.of(stateMessage));
        }

        /**
         * @param subnetId The OCID of the subnet for customer connected databases.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(@Nullable Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The OCID of the subnet for customer connected databases.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        /**
         * @param timeCreated The date and time the workspace was created, in the timestamp format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the workspace was created, in the timestamp format defined by RFC3339.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param vcnId The OCID of the VCN the subnet is in.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId The OCID of the VCN the subnet is in.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public WorkspaceState build() {
            return $;
        }
    }

}
