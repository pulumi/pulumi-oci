// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDataMaskRulesDataMaskRuleCollectionItem {
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    private String compartmentId;
    /**
     * @return Data Mask Categories
     * 
     */
    private List<String> dataMaskCategories;
    /**
     * @return The status of the dataMaskRule.
     * 
     */
    private String dataMaskRuleStatus;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The data mask rule description.
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
    private Map<String,Object> freeformTags;
    /**
     * @return OCID of iamGroup
     * 
     */
    private String iamGroupId;
    /**
     * @return Unique identifier that is immutable on creation
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private String lifecyleDetails;
    /**
     * @return The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
     * 
     */
    private List<GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected> targetSelecteds;
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the target was updated. Format defined by RFC3339.
     * 
     */
    private String timeUpdated;

    private GetDataMaskRulesDataMaskRuleCollectionItem() {}
    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Data Mask Categories
     * 
     */
    public List<String> dataMaskCategories() {
        return this.dataMaskCategories;
    }
    /**
     * @return The status of the dataMaskRule.
     * 
     */
    public String dataMaskRuleStatus() {
        return this.dataMaskRuleStatus;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The data mask rule description.
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
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return OCID of iamGroup
     * 
     */
    public String iamGroupId() {
        return this.iamGroupId;
    }
    /**
     * @return Unique identifier that is immutable on creation
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecyleDetails() {
        return this.lifecyleDetails;
    }
    /**
     * @return The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
     * 
     */
    public List<GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected> targetSelecteds() {
        return this.targetSelecteds;
    }
    /**
     * @return The date and time the target was created. Format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the target was updated. Format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDataMaskRulesDataMaskRuleCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<String> dataMaskCategories;
        private String dataMaskRuleStatus;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String iamGroupId;
        private String id;
        private String lifecyleDetails;
        private String state;
        private Map<String,Object> systemTags;
        private List<GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected> targetSelecteds;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetDataMaskRulesDataMaskRuleCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.dataMaskCategories = defaults.dataMaskCategories;
    	      this.dataMaskRuleStatus = defaults.dataMaskRuleStatus;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.iamGroupId = defaults.iamGroupId;
    	      this.id = defaults.id;
    	      this.lifecyleDetails = defaults.lifecyleDetails;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.targetSelecteds = defaults.targetSelecteds;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder dataMaskCategories(List<String> dataMaskCategories) {
            this.dataMaskCategories = Objects.requireNonNull(dataMaskCategories);
            return this;
        }
        public Builder dataMaskCategories(String... dataMaskCategories) {
            return dataMaskCategories(List.of(dataMaskCategories));
        }
        @CustomType.Setter
        public Builder dataMaskRuleStatus(String dataMaskRuleStatus) {
            this.dataMaskRuleStatus = Objects.requireNonNull(dataMaskRuleStatus);
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
        public Builder iamGroupId(String iamGroupId) {
            this.iamGroupId = Objects.requireNonNull(iamGroupId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lifecyleDetails(String lifecyleDetails) {
            this.lifecyleDetails = Objects.requireNonNull(lifecyleDetails);
            return this;
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
        public Builder targetSelecteds(List<GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected> targetSelecteds) {
            this.targetSelecteds = Objects.requireNonNull(targetSelecteds);
            return this;
        }
        public Builder targetSelecteds(GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected... targetSelecteds) {
            return targetSelecteds(List.of(targetSelecteds));
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
        public GetDataMaskRulesDataMaskRuleCollectionItem build() {
            final var o = new GetDataMaskRulesDataMaskRuleCollectionItem();
            o.compartmentId = compartmentId;
            o.dataMaskCategories = dataMaskCategories;
            o.dataMaskRuleStatus = dataMaskRuleStatus;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.iamGroupId = iamGroupId;
            o.id = id;
            o.lifecyleDetails = lifecyleDetails;
            o.state = state;
            o.systemTags = systemTags;
            o.targetSelecteds = targetSelecteds;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}