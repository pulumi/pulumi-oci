// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsManagementHub.outputs.GetLifecycleStageManagedInstanceId;
import com.pulumi.oci.OsManagementHub.outputs.GetLifecycleStageSoftwareSourceId;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetLifecycleStageResult {
    /**
     * @return The CPU architecture of the target instances.
     * 
     */
    private String archType;
    /**
     * @return The OCID of the tenancy containing the lifecycle stage.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Software source name.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the lifecycle environment for the lifecycle stage.
     * 
     */
    private String lifecycleEnvironmentId;
    private String lifecycleStageId;
    /**
     * @return The list of managed instances specified lifecycle stage.
     * 
     */
    private List<GetLifecycleStageManagedInstanceId> managedInstanceIds;
    /**
     * @return The operating system type of the target instances.
     * 
     */
    private String osFamily;
    /**
     * @return User specified rank for the lifecycle stage. Rank determines the hierarchy of the lifecycle stages for a given lifecycle environment.
     * 
     */
    private Integer rank;
    /**
     * @return Identifying information for the specified software source.
     * 
     */
    private List<GetLifecycleStageSoftwareSourceId> softwareSourceIds;
    /**
     * @return The current state of the lifecycle stage.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the lifecycle stage was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the lifecycle stage was last modified. An RFC3339 formatted datetime string.
     * 
     */
    private String timeModified;
    /**
     * @return The software source vendor name.
     * 
     */
    private String vendorName;

    private GetLifecycleStageResult() {}
    /**
     * @return The CPU architecture of the target instances.
     * 
     */
    public String archType() {
        return this.archType;
    }
    /**
     * @return The OCID of the tenancy containing the lifecycle stage.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Software source name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID of the lifecycle environment for the lifecycle stage.
     * 
     */
    public String lifecycleEnvironmentId() {
        return this.lifecycleEnvironmentId;
    }
    public String lifecycleStageId() {
        return this.lifecycleStageId;
    }
    /**
     * @return The list of managed instances specified lifecycle stage.
     * 
     */
    public List<GetLifecycleStageManagedInstanceId> managedInstanceIds() {
        return this.managedInstanceIds;
    }
    /**
     * @return The operating system type of the target instances.
     * 
     */
    public String osFamily() {
        return this.osFamily;
    }
    /**
     * @return User specified rank for the lifecycle stage. Rank determines the hierarchy of the lifecycle stages for a given lifecycle environment.
     * 
     */
    public Integer rank() {
        return this.rank;
    }
    /**
     * @return Identifying information for the specified software source.
     * 
     */
    public List<GetLifecycleStageSoftwareSourceId> softwareSourceIds() {
        return this.softwareSourceIds;
    }
    /**
     * @return The current state of the lifecycle stage.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the lifecycle stage was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the lifecycle stage was last modified. An RFC3339 formatted datetime string.
     * 
     */
    public String timeModified() {
        return this.timeModified;
    }
    /**
     * @return The software source vendor name.
     * 
     */
    public String vendorName() {
        return this.vendorName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLifecycleStageResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String archType;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleEnvironmentId;
        private String lifecycleStageId;
        private List<GetLifecycleStageManagedInstanceId> managedInstanceIds;
        private String osFamily;
        private Integer rank;
        private List<GetLifecycleStageSoftwareSourceId> softwareSourceIds;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeModified;
        private String vendorName;
        public Builder() {}
        public Builder(GetLifecycleStageResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archType = defaults.archType;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleEnvironmentId = defaults.lifecycleEnvironmentId;
    	      this.lifecycleStageId = defaults.lifecycleStageId;
    	      this.managedInstanceIds = defaults.managedInstanceIds;
    	      this.osFamily = defaults.osFamily;
    	      this.rank = defaults.rank;
    	      this.softwareSourceIds = defaults.softwareSourceIds;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeModified = defaults.timeModified;
    	      this.vendorName = defaults.vendorName;
        }

        @CustomType.Setter
        public Builder archType(String archType) {
            this.archType = Objects.requireNonNull(archType);
            return this;
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
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
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
        public Builder lifecycleEnvironmentId(String lifecycleEnvironmentId) {
            this.lifecycleEnvironmentId = Objects.requireNonNull(lifecycleEnvironmentId);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleStageId(String lifecycleStageId) {
            this.lifecycleStageId = Objects.requireNonNull(lifecycleStageId);
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceIds(List<GetLifecycleStageManagedInstanceId> managedInstanceIds) {
            this.managedInstanceIds = Objects.requireNonNull(managedInstanceIds);
            return this;
        }
        public Builder managedInstanceIds(GetLifecycleStageManagedInstanceId... managedInstanceIds) {
            return managedInstanceIds(List.of(managedInstanceIds));
        }
        @CustomType.Setter
        public Builder osFamily(String osFamily) {
            this.osFamily = Objects.requireNonNull(osFamily);
            return this;
        }
        @CustomType.Setter
        public Builder rank(Integer rank) {
            this.rank = Objects.requireNonNull(rank);
            return this;
        }
        @CustomType.Setter
        public Builder softwareSourceIds(List<GetLifecycleStageSoftwareSourceId> softwareSourceIds) {
            this.softwareSourceIds = Objects.requireNonNull(softwareSourceIds);
            return this;
        }
        public Builder softwareSourceIds(GetLifecycleStageSoftwareSourceId... softwareSourceIds) {
            return softwareSourceIds(List.of(softwareSourceIds));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeModified(String timeModified) {
            this.timeModified = Objects.requireNonNull(timeModified);
            return this;
        }
        @CustomType.Setter
        public Builder vendorName(String vendorName) {
            this.vendorName = Objects.requireNonNull(vendorName);
            return this;
        }
        public GetLifecycleStageResult build() {
            final var o = new GetLifecycleStageResult();
            o.archType = archType;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleEnvironmentId = lifecycleEnvironmentId;
            o.lifecycleStageId = lifecycleStageId;
            o.managedInstanceIds = managedInstanceIds;
            o.osFamily = osFamily;
            o.rank = rank;
            o.softwareSourceIds = softwareSourceIds;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeModified = timeModified;
            o.vendorName = vendorName;
            return o;
        }
    }
}