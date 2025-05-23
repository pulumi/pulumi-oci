// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetLifecycleEnvironmentManagedInstanceId;
import com.pulumi.oci.OsManagementHub.outputs.GetLifecycleEnvironmentStage;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetLifecycleEnvironmentResult {
    /**
     * @return The CPU architecture of the managed instances in the lifecycle stage.
     * 
     */
    private String archType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the lifecycle stage.
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
     * @return Software source name.
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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle environment that contains the lifecycle stage.
     * 
     */
    private String lifecycleEnvironmentId;
    /**
     * @return The location of managed instances associated with the lifecycle stage.
     * 
     */
    private String location;
    /**
     * @return The list of managed instances associated with the lifecycle stage.
     * 
     */
    private List<GetLifecycleEnvironmentManagedInstanceId> managedInstanceIds;
    /**
     * @return The operating system of the managed instances in the lifecycle stage.
     * 
     */
    private String osFamily;
    /**
     * @return User-specified list of lifecycle stages used within the lifecycle environment.
     * 
     */
    private List<GetLifecycleEnvironmentStage> stages;
    /**
     * @return The current state of the lifecycle environment.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time the lifecycle environment was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    private String timeCreated;
    /**
     * @return The time the lifecycle environment was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    private String timeModified;
    /**
     * @return The vendor of the operating system used by the managed instances in the lifecycle environment.
     * 
     */
    private String vendorName;

    private GetLifecycleEnvironmentResult() {}
    /**
     * @return The CPU architecture of the managed instances in the lifecycle stage.
     * 
     */
    public String archType() {
        return this.archType;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the lifecycle stage.
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
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle environment that contains the lifecycle stage.
     * 
     */
    public String lifecycleEnvironmentId() {
        return this.lifecycleEnvironmentId;
    }
    /**
     * @return The location of managed instances associated with the lifecycle stage.
     * 
     */
    public String location() {
        return this.location;
    }
    /**
     * @return The list of managed instances associated with the lifecycle stage.
     * 
     */
    public List<GetLifecycleEnvironmentManagedInstanceId> managedInstanceIds() {
        return this.managedInstanceIds;
    }
    /**
     * @return The operating system of the managed instances in the lifecycle stage.
     * 
     */
    public String osFamily() {
        return this.osFamily;
    }
    /**
     * @return User-specified list of lifecycle stages used within the lifecycle environment.
     * 
     */
    public List<GetLifecycleEnvironmentStage> stages() {
        return this.stages;
    }
    /**
     * @return The current state of the lifecycle environment.
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
     * @return The time the lifecycle environment was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the lifecycle environment was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
     * 
     */
    public String timeModified() {
        return this.timeModified;
    }
    /**
     * @return The vendor of the operating system used by the managed instances in the lifecycle environment.
     * 
     */
    public String vendorName() {
        return this.vendorName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLifecycleEnvironmentResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String archType;
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleEnvironmentId;
        private String location;
        private List<GetLifecycleEnvironmentManagedInstanceId> managedInstanceIds;
        private String osFamily;
        private List<GetLifecycleEnvironmentStage> stages;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeModified;
        private String vendorName;
        public Builder() {}
        public Builder(GetLifecycleEnvironmentResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archType = defaults.archType;
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleEnvironmentId = defaults.lifecycleEnvironmentId;
    	      this.location = defaults.location;
    	      this.managedInstanceIds = defaults.managedInstanceIds;
    	      this.osFamily = defaults.osFamily;
    	      this.stages = defaults.stages;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeModified = defaults.timeModified;
    	      this.vendorName = defaults.vendorName;
        }

        @CustomType.Setter
        public Builder archType(String archType) {
            if (archType == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "archType");
            }
            this.archType = archType;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleEnvironmentId(String lifecycleEnvironmentId) {
            if (lifecycleEnvironmentId == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "lifecycleEnvironmentId");
            }
            this.lifecycleEnvironmentId = lifecycleEnvironmentId;
            return this;
        }
        @CustomType.Setter
        public Builder location(String location) {
            if (location == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "location");
            }
            this.location = location;
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceIds(List<GetLifecycleEnvironmentManagedInstanceId> managedInstanceIds) {
            if (managedInstanceIds == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "managedInstanceIds");
            }
            this.managedInstanceIds = managedInstanceIds;
            return this;
        }
        public Builder managedInstanceIds(GetLifecycleEnvironmentManagedInstanceId... managedInstanceIds) {
            return managedInstanceIds(List.of(managedInstanceIds));
        }
        @CustomType.Setter
        public Builder osFamily(String osFamily) {
            if (osFamily == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "osFamily");
            }
            this.osFamily = osFamily;
            return this;
        }
        @CustomType.Setter
        public Builder stages(List<GetLifecycleEnvironmentStage> stages) {
            if (stages == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "stages");
            }
            this.stages = stages;
            return this;
        }
        public Builder stages(GetLifecycleEnvironmentStage... stages) {
            return stages(List.of(stages));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeModified(String timeModified) {
            if (timeModified == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "timeModified");
            }
            this.timeModified = timeModified;
            return this;
        }
        @CustomType.Setter
        public Builder vendorName(String vendorName) {
            if (vendorName == null) {
              throw new MissingRequiredPropertyException("GetLifecycleEnvironmentResult", "vendorName");
            }
            this.vendorName = vendorName;
            return this;
        }
        public GetLifecycleEnvironmentResult build() {
            final var _resultValue = new GetLifecycleEnvironmentResult();
            _resultValue.archType = archType;
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleEnvironmentId = lifecycleEnvironmentId;
            _resultValue.location = location;
            _resultValue.managedInstanceIds = managedInstanceIds;
            _resultValue.osFamily = osFamily;
            _resultValue.stages = stages;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeModified = timeModified;
            _resultValue.vendorName = vendorName;
            return _resultValue;
        }
    }
}
