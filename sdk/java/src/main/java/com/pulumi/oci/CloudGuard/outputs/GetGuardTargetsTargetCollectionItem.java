// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollectionItemTargetDetail;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollectionItemTargetDetectorRecipe;
import com.pulumi.oci.CloudGuard.outputs.GetGuardTargetsTargetCollectionItemTargetResponderRecipe;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetGuardTargetsTargetCollectionItem {
    /**
     * @return The OCID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Responder rule description
     * 
     */
    private String description;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Unique identifier of target responder recipe that can&#39;t be changed after creation
     * 
     */
    private String id;
    /**
     * @return List of inherited compartments
     * 
     */
    private List<String> inheritedByCompartments;
    /**
     * @return A message describing the current lifecycle state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
     * 
     */
    private String lifecyleDetails;
    /**
     * @return Total number of recipes attached to target
     * 
     */
    private Integer recipeCount;
    /**
     * @return The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return Details specific to the target type.
     * 
     */
    private List<GetGuardTargetsTargetCollectionItemTargetDetail> targetDetails;
    /**
     * @return List of detector recipes attached to target
     * 
     */
    private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipe> targetDetectorRecipes;
    /**
     * @return Resource ID which the target uses to monitor
     * 
     */
    private String targetResourceId;
    /**
     * @return Type of target
     * 
     */
    private String targetResourceType;
    /**
     * @return List of responder recipes attached to target
     * 
     */
    private List<GetGuardTargetsTargetCollectionItemTargetResponderRecipe> targetResponderRecipes;
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the target was last updated. Format defined by RFC3339.
     * 
     */
    private String timeUpdated;

    private GetGuardTargetsTargetCollectionItem() {}
    /**
     * @return The OCID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Responder rule description
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Unique identifier of target responder recipe that can&#39;t be changed after creation
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return List of inherited compartments
     * 
     */
    public List<String> inheritedByCompartments() {
        return this.inheritedByCompartments;
    }
    /**
     * @return A message describing the current lifecycle state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
     * 
     */
    public String lifecyleDetails() {
        return this.lifecyleDetails;
    }
    /**
     * @return Total number of recipes attached to target
     * 
     */
    public Integer recipeCount() {
        return this.recipeCount;
    }
    /**
     * @return The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return Details specific to the target type.
     * 
     */
    public List<GetGuardTargetsTargetCollectionItemTargetDetail> targetDetails() {
        return this.targetDetails;
    }
    /**
     * @return List of detector recipes attached to target
     * 
     */
    public List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipe> targetDetectorRecipes() {
        return this.targetDetectorRecipes;
    }
    /**
     * @return Resource ID which the target uses to monitor
     * 
     */
    public String targetResourceId() {
        return this.targetResourceId;
    }
    /**
     * @return Type of target
     * 
     */
    public String targetResourceType() {
        return this.targetResourceType;
    }
    /**
     * @return List of responder recipes attached to target
     * 
     */
    public List<GetGuardTargetsTargetCollectionItemTargetResponderRecipe> targetResponderRecipes() {
        return this.targetResponderRecipes;
    }
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the target was last updated. Format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetGuardTargetsTargetCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private List<String> inheritedByCompartments;
        private String lifecyleDetails;
        private Integer recipeCount;
        private String state;
        private Map<String,String> systemTags;
        private List<GetGuardTargetsTargetCollectionItemTargetDetail> targetDetails;
        private List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipe> targetDetectorRecipes;
        private String targetResourceId;
        private String targetResourceType;
        private List<GetGuardTargetsTargetCollectionItemTargetResponderRecipe> targetResponderRecipes;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetGuardTargetsTargetCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.inheritedByCompartments = defaults.inheritedByCompartments;
    	      this.lifecyleDetails = defaults.lifecyleDetails;
    	      this.recipeCount = defaults.recipeCount;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.targetDetails = defaults.targetDetails;
    	      this.targetDetectorRecipes = defaults.targetDetectorRecipes;
    	      this.targetResourceId = defaults.targetResourceId;
    	      this.targetResourceType = defaults.targetResourceType;
    	      this.targetResponderRecipes = defaults.targetResponderRecipes;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder inheritedByCompartments(List<String> inheritedByCompartments) {
            if (inheritedByCompartments == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "inheritedByCompartments");
            }
            this.inheritedByCompartments = inheritedByCompartments;
            return this;
        }
        public Builder inheritedByCompartments(String... inheritedByCompartments) {
            return inheritedByCompartments(List.of(inheritedByCompartments));
        }
        @CustomType.Setter
        public Builder lifecyleDetails(String lifecyleDetails) {
            if (lifecyleDetails == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "lifecyleDetails");
            }
            this.lifecyleDetails = lifecyleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder recipeCount(Integer recipeCount) {
            if (recipeCount == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "recipeCount");
            }
            this.recipeCount = recipeCount;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder targetDetails(List<GetGuardTargetsTargetCollectionItemTargetDetail> targetDetails) {
            if (targetDetails == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "targetDetails");
            }
            this.targetDetails = targetDetails;
            return this;
        }
        public Builder targetDetails(GetGuardTargetsTargetCollectionItemTargetDetail... targetDetails) {
            return targetDetails(List.of(targetDetails));
        }
        @CustomType.Setter
        public Builder targetDetectorRecipes(List<GetGuardTargetsTargetCollectionItemTargetDetectorRecipe> targetDetectorRecipes) {
            if (targetDetectorRecipes == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "targetDetectorRecipes");
            }
            this.targetDetectorRecipes = targetDetectorRecipes;
            return this;
        }
        public Builder targetDetectorRecipes(GetGuardTargetsTargetCollectionItemTargetDetectorRecipe... targetDetectorRecipes) {
            return targetDetectorRecipes(List.of(targetDetectorRecipes));
        }
        @CustomType.Setter
        public Builder targetResourceId(String targetResourceId) {
            if (targetResourceId == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "targetResourceId");
            }
            this.targetResourceId = targetResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder targetResourceType(String targetResourceType) {
            if (targetResourceType == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "targetResourceType");
            }
            this.targetResourceType = targetResourceType;
            return this;
        }
        @CustomType.Setter
        public Builder targetResponderRecipes(List<GetGuardTargetsTargetCollectionItemTargetResponderRecipe> targetResponderRecipes) {
            if (targetResponderRecipes == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "targetResponderRecipes");
            }
            this.targetResponderRecipes = targetResponderRecipes;
            return this;
        }
        public Builder targetResponderRecipes(GetGuardTargetsTargetCollectionItemTargetResponderRecipe... targetResponderRecipes) {
            return targetResponderRecipes(List.of(targetResponderRecipes));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetGuardTargetsTargetCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetGuardTargetsTargetCollectionItem build() {
            final var _resultValue = new GetGuardTargetsTargetCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.inheritedByCompartments = inheritedByCompartments;
            _resultValue.lifecyleDetails = lifecyleDetails;
            _resultValue.recipeCount = recipeCount;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.targetDetails = targetDetails;
            _resultValue.targetDetectorRecipes = targetDetectorRecipes;
            _resultValue.targetResourceId = targetResourceId;
            _resultValue.targetResourceType = targetResourceType;
            _resultValue.targetResponderRecipes = targetResponderRecipes;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
