// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsManagementHub.outputs.GetProfilesProfileCollectionItemLifecycleEnvironment;
import com.pulumi.oci.OsManagementHub.outputs.GetProfilesProfileCollectionItemLifecycleStage;
import com.pulumi.oci.OsManagementHub.outputs.GetProfilesProfileCollectionItemManagedInstanceGroup;
import com.pulumi.oci.OsManagementHub.outputs.GetProfilesProfileCollectionItemSoftwareSource;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetProfilesProfileCollectionItem {
    /**
     * @return A filter to return only profiles that match the given archType.
     * 
     */
    private String archType;
    /**
     * @return The OCID of the compartment that contains the resources to list.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Software source description.
     * 
     */
    private String description;
    /**
     * @return A filter to return resources that match the given display names.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of the software source.
     * 
     */
    private String id;
    /**
     * @return Identifying information for the specified lifecycle environment.
     * 
     */
    private List<GetProfilesProfileCollectionItemLifecycleEnvironment> lifecycleEnvironments;
    private String lifecycleStageId;
    /**
     * @return Identifying information for the specified lifecycle stage.
     * 
     */
    private List<GetProfilesProfileCollectionItemLifecycleStage> lifecycleStages;
    private String managedInstanceGroupId;
    /**
     * @return Identifying information for the specified managed instance group.
     * 
     */
    private List<GetProfilesProfileCollectionItemManagedInstanceGroup> managedInstanceGroups;
    /**
     * @return The OCID of the management station.
     * 
     */
    private String managementStationId;
    /**
     * @return A filter to return only profiles that match the given osFamily.
     * 
     */
    private String osFamily;
    /**
     * @return A filter to return registration profiles that match the given profileType.
     * 
     */
    private String profileType;
    private List<String> softwareSourceIds;
    /**
     * @return The list of software sources that the registration profile will use.
     * 
     */
    private List<GetProfilesProfileCollectionItemSoftwareSource> softwareSources;
    /**
     * @return A filter to return only registration profile whose lifecycleState matches the given lifecycleState.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time the the registration profile was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return A filter to return only profiles that match the given vendorName.
     * 
     */
    private String vendorName;

    private GetProfilesProfileCollectionItem() {}
    /**
     * @return A filter to return only profiles that match the given archType.
     * 
     */
    public String archType() {
        return this.archType;
    }
    /**
     * @return The OCID of the compartment that contains the resources to list.
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
     * @return Software source description.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return resources that match the given display names.
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
     * @return The OCID of the software source.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Identifying information for the specified lifecycle environment.
     * 
     */
    public List<GetProfilesProfileCollectionItemLifecycleEnvironment> lifecycleEnvironments() {
        return this.lifecycleEnvironments;
    }
    public String lifecycleStageId() {
        return this.lifecycleStageId;
    }
    /**
     * @return Identifying information for the specified lifecycle stage.
     * 
     */
    public List<GetProfilesProfileCollectionItemLifecycleStage> lifecycleStages() {
        return this.lifecycleStages;
    }
    public String managedInstanceGroupId() {
        return this.managedInstanceGroupId;
    }
    /**
     * @return Identifying information for the specified managed instance group.
     * 
     */
    public List<GetProfilesProfileCollectionItemManagedInstanceGroup> managedInstanceGroups() {
        return this.managedInstanceGroups;
    }
    /**
     * @return The OCID of the management station.
     * 
     */
    public String managementStationId() {
        return this.managementStationId;
    }
    /**
     * @return A filter to return only profiles that match the given osFamily.
     * 
     */
    public String osFamily() {
        return this.osFamily;
    }
    /**
     * @return A filter to return registration profiles that match the given profileType.
     * 
     */
    public String profileType() {
        return this.profileType;
    }
    public List<String> softwareSourceIds() {
        return this.softwareSourceIds;
    }
    /**
     * @return The list of software sources that the registration profile will use.
     * 
     */
    public List<GetProfilesProfileCollectionItemSoftwareSource> softwareSources() {
        return this.softwareSources;
    }
    /**
     * @return A filter to return only registration profile whose lifecycleState matches the given lifecycleState.
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
     * @return The time the the registration profile was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return A filter to return only profiles that match the given vendorName.
     * 
     */
    public String vendorName() {
        return this.vendorName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProfilesProfileCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String archType;
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private List<GetProfilesProfileCollectionItemLifecycleEnvironment> lifecycleEnvironments;
        private String lifecycleStageId;
        private List<GetProfilesProfileCollectionItemLifecycleStage> lifecycleStages;
        private String managedInstanceGroupId;
        private List<GetProfilesProfileCollectionItemManagedInstanceGroup> managedInstanceGroups;
        private String managementStationId;
        private String osFamily;
        private String profileType;
        private List<String> softwareSourceIds;
        private List<GetProfilesProfileCollectionItemSoftwareSource> softwareSources;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String vendorName;
        public Builder() {}
        public Builder(GetProfilesProfileCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archType = defaults.archType;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleEnvironments = defaults.lifecycleEnvironments;
    	      this.lifecycleStageId = defaults.lifecycleStageId;
    	      this.lifecycleStages = defaults.lifecycleStages;
    	      this.managedInstanceGroupId = defaults.managedInstanceGroupId;
    	      this.managedInstanceGroups = defaults.managedInstanceGroups;
    	      this.managementStationId = defaults.managementStationId;
    	      this.osFamily = defaults.osFamily;
    	      this.profileType = defaults.profileType;
    	      this.softwareSourceIds = defaults.softwareSourceIds;
    	      this.softwareSources = defaults.softwareSources;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
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
        public Builder lifecycleEnvironments(List<GetProfilesProfileCollectionItemLifecycleEnvironment> lifecycleEnvironments) {
            this.lifecycleEnvironments = Objects.requireNonNull(lifecycleEnvironments);
            return this;
        }
        public Builder lifecycleEnvironments(GetProfilesProfileCollectionItemLifecycleEnvironment... lifecycleEnvironments) {
            return lifecycleEnvironments(List.of(lifecycleEnvironments));
        }
        @CustomType.Setter
        public Builder lifecycleStageId(String lifecycleStageId) {
            this.lifecycleStageId = Objects.requireNonNull(lifecycleStageId);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleStages(List<GetProfilesProfileCollectionItemLifecycleStage> lifecycleStages) {
            this.lifecycleStages = Objects.requireNonNull(lifecycleStages);
            return this;
        }
        public Builder lifecycleStages(GetProfilesProfileCollectionItemLifecycleStage... lifecycleStages) {
            return lifecycleStages(List.of(lifecycleStages));
        }
        @CustomType.Setter
        public Builder managedInstanceGroupId(String managedInstanceGroupId) {
            this.managedInstanceGroupId = Objects.requireNonNull(managedInstanceGroupId);
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceGroups(List<GetProfilesProfileCollectionItemManagedInstanceGroup> managedInstanceGroups) {
            this.managedInstanceGroups = Objects.requireNonNull(managedInstanceGroups);
            return this;
        }
        public Builder managedInstanceGroups(GetProfilesProfileCollectionItemManagedInstanceGroup... managedInstanceGroups) {
            return managedInstanceGroups(List.of(managedInstanceGroups));
        }
        @CustomType.Setter
        public Builder managementStationId(String managementStationId) {
            this.managementStationId = Objects.requireNonNull(managementStationId);
            return this;
        }
        @CustomType.Setter
        public Builder osFamily(String osFamily) {
            this.osFamily = Objects.requireNonNull(osFamily);
            return this;
        }
        @CustomType.Setter
        public Builder profileType(String profileType) {
            this.profileType = Objects.requireNonNull(profileType);
            return this;
        }
        @CustomType.Setter
        public Builder softwareSourceIds(List<String> softwareSourceIds) {
            this.softwareSourceIds = Objects.requireNonNull(softwareSourceIds);
            return this;
        }
        public Builder softwareSourceIds(String... softwareSourceIds) {
            return softwareSourceIds(List.of(softwareSourceIds));
        }
        @CustomType.Setter
        public Builder softwareSources(List<GetProfilesProfileCollectionItemSoftwareSource> softwareSources) {
            this.softwareSources = Objects.requireNonNull(softwareSources);
            return this;
        }
        public Builder softwareSources(GetProfilesProfileCollectionItemSoftwareSource... softwareSources) {
            return softwareSources(List.of(softwareSources));
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
        public Builder vendorName(String vendorName) {
            this.vendorName = Objects.requireNonNull(vendorName);
            return this;
        }
        public GetProfilesProfileCollectionItem build() {
            final var o = new GetProfilesProfileCollectionItem();
            o.archType = archType;
            o.compartmentId = compartmentId;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleEnvironments = lifecycleEnvironments;
            o.lifecycleStageId = lifecycleStageId;
            o.lifecycleStages = lifecycleStages;
            o.managedInstanceGroupId = managedInstanceGroupId;
            o.managedInstanceGroups = managedInstanceGroups;
            o.managementStationId = managementStationId;
            o.osFamily = osFamily;
            o.profileType = profileType;
            o.softwareSourceIds = softwareSourceIds;
            o.softwareSources = softwareSources;
            o.state = state;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.vendorName = vendorName;
            return o;
        }
    }
}