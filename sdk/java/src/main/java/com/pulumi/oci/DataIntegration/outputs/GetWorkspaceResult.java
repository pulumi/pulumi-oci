// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetWorkspaceResult {
    /**
     * @return The OCID of the compartment that contains the workspace.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A user defined description for the workspace.
     * 
     */
    private String description;
    /**
     * @return A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return The IP of the custom DNS.
     * 
     */
    private String dnsServerIp;
    /**
     * @return The DNS zone of the custom DNS to use to resolve names.
     * 
     */
    private String dnsServerZone;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return A system-generated and immutable identifier assigned to the workspace upon creation.
     * 
     */
    private String id;
    private Boolean isForceOperation;
    /**
     * @return Specifies whether the private network connection is enabled or disabled.
     * 
     */
    private Boolean isPrivateNetworkEnabled;
    private Integer quiesceTimeout;
    /**
     * @return Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn&#39;t available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
     * 
     */
    private String state;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     * 
     */
    private String stateMessage;
    /**
     * @return The OCID of the subnet for customer connected databases.
     * 
     */
    private String subnetId;
    /**
     * @return The date and time the workspace was created, in the timestamp format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeUpdated;
    /**
     * @return The OCID of the VCN the subnet is in.
     * 
     */
    private String vcnId;
    private String workspaceId;

    private GetWorkspaceResult() {}
    /**
     * @return The OCID of the compartment that contains the workspace.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user defined description for the workspace.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The IP of the custom DNS.
     * 
     */
    public String dnsServerIp() {
        return this.dnsServerIp;
    }
    /**
     * @return The DNS zone of the custom DNS to use to resolve names.
     * 
     */
    public String dnsServerZone() {
        return this.dnsServerZone;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return A system-generated and immutable identifier assigned to the workspace upon creation.
     * 
     */
    public String id() {
        return this.id;
    }
    public Boolean isForceOperation() {
        return this.isForceOperation;
    }
    /**
     * @return Specifies whether the private network connection is enabled or disabled.
     * 
     */
    public Boolean isPrivateNetworkEnabled() {
        return this.isPrivateNetworkEnabled;
    }
    public Integer quiesceTimeout() {
        return this.quiesceTimeout;
    }
    /**
     * @return Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn&#39;t available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     * 
     */
    public String stateMessage() {
        return this.stateMessage;
    }
    /**
     * @return The OCID of the subnet for customer connected databases.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return The date and time the workspace was created, in the timestamp format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The OCID of the VCN the subnet is in.
     * 
     */
    public String vcnId() {
        return this.vcnId;
    }
    public String workspaceId() {
        return this.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private String dnsServerIp;
        private String dnsServerZone;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isForceOperation;
        private Boolean isPrivateNetworkEnabled;
        private Integer quiesceTimeout;
        private String state;
        private String stateMessage;
        private String subnetId;
        private String timeCreated;
        private String timeUpdated;
        private String vcnId;
        private String workspaceId;
        public Builder() {}
        public Builder(GetWorkspaceResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.dnsServerIp = defaults.dnsServerIp;
    	      this.dnsServerZone = defaults.dnsServerZone;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isForceOperation = defaults.isForceOperation;
    	      this.isPrivateNetworkEnabled = defaults.isPrivateNetworkEnabled;
    	      this.quiesceTimeout = defaults.quiesceTimeout;
    	      this.state = defaults.state;
    	      this.stateMessage = defaults.stateMessage;
    	      this.subnetId = defaults.subnetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.vcnId = defaults.vcnId;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder dnsServerIp(String dnsServerIp) {
            this.dnsServerIp = Objects.requireNonNull(dnsServerIp);
            return this;
        }
        @CustomType.Setter
        public Builder dnsServerZone(String dnsServerZone) {
            this.dnsServerZone = Objects.requireNonNull(dnsServerZone);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isForceOperation(Boolean isForceOperation) {
            this.isForceOperation = Objects.requireNonNull(isForceOperation);
            return this;
        }
        @CustomType.Setter
        public Builder isPrivateNetworkEnabled(Boolean isPrivateNetworkEnabled) {
            this.isPrivateNetworkEnabled = Objects.requireNonNull(isPrivateNetworkEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder quiesceTimeout(Integer quiesceTimeout) {
            this.quiesceTimeout = Objects.requireNonNull(quiesceTimeout);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder stateMessage(String stateMessage) {
            this.stateMessage = Objects.requireNonNull(stateMessage);
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder vcnId(String vcnId) {
            this.vcnId = Objects.requireNonNull(vcnId);
            return this;
        }
        @CustomType.Setter
        public Builder workspaceId(String workspaceId) {
            this.workspaceId = Objects.requireNonNull(workspaceId);
            return this;
        }
        public GetWorkspaceResult build() {
            final var o = new GetWorkspaceResult();
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.dnsServerIp = dnsServerIp;
            o.dnsServerZone = dnsServerZone;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isForceOperation = isForceOperation;
            o.isPrivateNetworkEnabled = isPrivateNetworkEnabled;
            o.quiesceTimeout = quiesceTimeout;
            o.state = state;
            o.stateMessage = stateMessage;
            o.subnetId = subnetId;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.vcnId = vcnId;
            o.workspaceId = workspaceId;
            return o;
        }
    }
}