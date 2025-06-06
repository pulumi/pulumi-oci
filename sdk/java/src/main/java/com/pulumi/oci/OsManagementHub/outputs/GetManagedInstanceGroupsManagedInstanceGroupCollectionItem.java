// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceGroupsManagedInstanceGroupCollectionItemAutonomousSetting;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceGroupsManagedInstanceGroupCollectionItemSoftwareSource;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetManagedInstanceGroupsManagedInstanceGroupCollectionItem {
    /**
     * @return A filter to return only profiles that match the given archType.
     * 
     */
    private String archType;
    /**
     * @return Settings for the Autonomous Linux service.
     * 
     */
    private List<GetManagedInstanceGroupsManagedInstanceGroupCollectionItemAutonomousSetting> autonomousSettings;
    /**
     * @return (Updatable) The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
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
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     * 
     */
    private String id;
    /**
     * @return Indicates whether to list only resources managed by the Autonomous Linux service.
     * 
     */
    private Boolean isManagedByAutonomousLinux;
    /**
     * @return A filter to return only resources whose location matches the given value.
     * 
     */
    private String location;
    /**
     * @return The number of managed instances in the group.
     * 
     */
    private Integer managedInstanceCount;
    /**
     * @return The list of managed instance [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) attached to the managed instance group.
     * 
     */
    private List<String> managedInstanceIds;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Oracle Notifications service (ONS) topic. ONS is the channel used to send notifications to the customer.
     * 
     */
    private String notificationTopicId;
    /**
     * @return A filter to return only resources that match the given operating system family.
     * 
     */
    private String osFamily;
    /**
     * @return The number of scheduled jobs pending against the managed instance group.
     * 
     */
    private Integer pendingJobCount;
    /**
     * @return The list of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that the managed instance group will use.
     * 
     */
    private List<String> softwareSourceIds;
    /**
     * @return The list of software sources that the managed instance group will use.
     * 
     */
    private List<GetManagedInstanceGroupsManagedInstanceGroupCollectionItemSoftwareSource> softwareSources;
    /**
     * @return A filter to return only managed instance groups that are in the specified state.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time the managed instance group was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    private String timeCreated;
    /**
     * @return The time the managed instance group was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    private String timeModified;
    /**
     * @return The vendor of the operating system used by the managed instances in the group.
     * 
     */
    private String vendorName;

    private GetManagedInstanceGroupsManagedInstanceGroupCollectionItem() {}
    /**
     * @return A filter to return only profiles that match the given archType.
     * 
     */
    public String archType() {
        return this.archType;
    }
    /**
     * @return Settings for the Autonomous Linux service.
     * 
     */
    public List<GetManagedInstanceGroupsManagedInstanceGroupCollectionItemAutonomousSetting> autonomousSettings() {
        return this.autonomousSettings;
    }
    /**
     * @return (Updatable) The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
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
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether to list only resources managed by the Autonomous Linux service.
     * 
     */
    public Boolean isManagedByAutonomousLinux() {
        return this.isManagedByAutonomousLinux;
    }
    /**
     * @return A filter to return only resources whose location matches the given value.
     * 
     */
    public String location() {
        return this.location;
    }
    /**
     * @return The number of managed instances in the group.
     * 
     */
    public Integer managedInstanceCount() {
        return this.managedInstanceCount;
    }
    /**
     * @return The list of managed instance [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) attached to the managed instance group.
     * 
     */
    public List<String> managedInstanceIds() {
        return this.managedInstanceIds;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Oracle Notifications service (ONS) topic. ONS is the channel used to send notifications to the customer.
     * 
     */
    public String notificationTopicId() {
        return this.notificationTopicId;
    }
    /**
     * @return A filter to return only resources that match the given operating system family.
     * 
     */
    public String osFamily() {
        return this.osFamily;
    }
    /**
     * @return The number of scheduled jobs pending against the managed instance group.
     * 
     */
    public Integer pendingJobCount() {
        return this.pendingJobCount;
    }
    /**
     * @return The list of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that the managed instance group will use.
     * 
     */
    public List<String> softwareSourceIds() {
        return this.softwareSourceIds;
    }
    /**
     * @return The list of software sources that the managed instance group will use.
     * 
     */
    public List<GetManagedInstanceGroupsManagedInstanceGroupCollectionItemSoftwareSource> softwareSources() {
        return this.softwareSources;
    }
    /**
     * @return A filter to return only managed instance groups that are in the specified state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the managed instance group was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the managed instance group was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public String timeModified() {
        return this.timeModified;
    }
    /**
     * @return The vendor of the operating system used by the managed instances in the group.
     * 
     */
    public String vendorName() {
        return this.vendorName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceGroupsManagedInstanceGroupCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String archType;
        private List<GetManagedInstanceGroupsManagedInstanceGroupCollectionItemAutonomousSetting> autonomousSettings;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isManagedByAutonomousLinux;
        private String location;
        private Integer managedInstanceCount;
        private List<String> managedInstanceIds;
        private String notificationTopicId;
        private String osFamily;
        private Integer pendingJobCount;
        private List<String> softwareSourceIds;
        private List<GetManagedInstanceGroupsManagedInstanceGroupCollectionItemSoftwareSource> softwareSources;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeModified;
        private String vendorName;
        public Builder() {}
        public Builder(GetManagedInstanceGroupsManagedInstanceGroupCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archType = defaults.archType;
    	      this.autonomousSettings = defaults.autonomousSettings;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isManagedByAutonomousLinux = defaults.isManagedByAutonomousLinux;
    	      this.location = defaults.location;
    	      this.managedInstanceCount = defaults.managedInstanceCount;
    	      this.managedInstanceIds = defaults.managedInstanceIds;
    	      this.notificationTopicId = defaults.notificationTopicId;
    	      this.osFamily = defaults.osFamily;
    	      this.pendingJobCount = defaults.pendingJobCount;
    	      this.softwareSourceIds = defaults.softwareSourceIds;
    	      this.softwareSources = defaults.softwareSources;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeModified = defaults.timeModified;
    	      this.vendorName = defaults.vendorName;
        }

        @CustomType.Setter
        public Builder archType(String archType) {
            if (archType == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "archType");
            }
            this.archType = archType;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousSettings(List<GetManagedInstanceGroupsManagedInstanceGroupCollectionItemAutonomousSetting> autonomousSettings) {
            if (autonomousSettings == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "autonomousSettings");
            }
            this.autonomousSettings = autonomousSettings;
            return this;
        }
        public Builder autonomousSettings(GetManagedInstanceGroupsManagedInstanceGroupCollectionItemAutonomousSetting... autonomousSettings) {
            return autonomousSettings(List.of(autonomousSettings));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isManagedByAutonomousLinux(Boolean isManagedByAutonomousLinux) {
            if (isManagedByAutonomousLinux == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "isManagedByAutonomousLinux");
            }
            this.isManagedByAutonomousLinux = isManagedByAutonomousLinux;
            return this;
        }
        @CustomType.Setter
        public Builder location(String location) {
            if (location == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "location");
            }
            this.location = location;
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceCount(Integer managedInstanceCount) {
            if (managedInstanceCount == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "managedInstanceCount");
            }
            this.managedInstanceCount = managedInstanceCount;
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceIds(List<String> managedInstanceIds) {
            if (managedInstanceIds == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "managedInstanceIds");
            }
            this.managedInstanceIds = managedInstanceIds;
            return this;
        }
        public Builder managedInstanceIds(String... managedInstanceIds) {
            return managedInstanceIds(List.of(managedInstanceIds));
        }
        @CustomType.Setter
        public Builder notificationTopicId(String notificationTopicId) {
            if (notificationTopicId == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "notificationTopicId");
            }
            this.notificationTopicId = notificationTopicId;
            return this;
        }
        @CustomType.Setter
        public Builder osFamily(String osFamily) {
            if (osFamily == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "osFamily");
            }
            this.osFamily = osFamily;
            return this;
        }
        @CustomType.Setter
        public Builder pendingJobCount(Integer pendingJobCount) {
            if (pendingJobCount == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "pendingJobCount");
            }
            this.pendingJobCount = pendingJobCount;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSourceIds(List<String> softwareSourceIds) {
            if (softwareSourceIds == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "softwareSourceIds");
            }
            this.softwareSourceIds = softwareSourceIds;
            return this;
        }
        public Builder softwareSourceIds(String... softwareSourceIds) {
            return softwareSourceIds(List.of(softwareSourceIds));
        }
        @CustomType.Setter
        public Builder softwareSources(List<GetManagedInstanceGroupsManagedInstanceGroupCollectionItemSoftwareSource> softwareSources) {
            if (softwareSources == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "softwareSources");
            }
            this.softwareSources = softwareSources;
            return this;
        }
        public Builder softwareSources(GetManagedInstanceGroupsManagedInstanceGroupCollectionItemSoftwareSource... softwareSources) {
            return softwareSources(List.of(softwareSources));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeModified(String timeModified) {
            if (timeModified == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "timeModified");
            }
            this.timeModified = timeModified;
            return this;
        }
        @CustomType.Setter
        public Builder vendorName(String vendorName) {
            if (vendorName == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupsManagedInstanceGroupCollectionItem", "vendorName");
            }
            this.vendorName = vendorName;
            return this;
        }
        public GetManagedInstanceGroupsManagedInstanceGroupCollectionItem build() {
            final var _resultValue = new GetManagedInstanceGroupsManagedInstanceGroupCollectionItem();
            _resultValue.archType = archType;
            _resultValue.autonomousSettings = autonomousSettings;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isManagedByAutonomousLinux = isManagedByAutonomousLinux;
            _resultValue.location = location;
            _resultValue.managedInstanceCount = managedInstanceCount;
            _resultValue.managedInstanceIds = managedInstanceIds;
            _resultValue.notificationTopicId = notificationTopicId;
            _resultValue.osFamily = osFamily;
            _resultValue.pendingJobCount = pendingJobCount;
            _resultValue.softwareSourceIds = softwareSourceIds;
            _resultValue.softwareSources = softwareSources;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeModified = timeModified;
            _resultValue.vendorName = vendorName;
            return _resultValue;
        }
    }
}
