// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetManagedListsManagedListCollectionItem {
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
     * @return Managed list description
     * 
     */
    private String description;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return Provider of the managed list feed
     * 
     */
    private String feedProvider;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return Unique identifier that can&#39;t be changed after creation
     * 
     */
    private String id;
    /**
     * @return Is this list editable?
     * 
     */
    private Boolean isEditable;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
     * 
     */
    private String lifecyleDetails;
    /**
     * @return List of items in the managed list
     * 
     */
    private List<String> listItems;
    /**
     * @return The type of managed list.
     * 
     */
    private String listType;
    /**
     * @return OCID of the source managed list
     * 
     */
    private String sourceManagedListId;
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
     * @return The date and time the managed list was created. Format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the managed list was last updated. Format defined by RFC3339.
     * 
     */
    private String timeUpdated;

    private GetManagedListsManagedListCollectionItem() {}
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
     * @return Managed list description
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
     * @return Provider of the managed list feed
     * 
     */
    public String feedProvider() {
        return this.feedProvider;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return Unique identifier that can&#39;t be changed after creation
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Is this list editable?
     * 
     */
    public Boolean isEditable() {
        return this.isEditable;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
     * 
     */
    public String lifecyleDetails() {
        return this.lifecyleDetails;
    }
    /**
     * @return List of items in the managed list
     * 
     */
    public List<String> listItems() {
        return this.listItems;
    }
    /**
     * @return The type of managed list.
     * 
     */
    public String listType() {
        return this.listType;
    }
    /**
     * @return OCID of the source managed list
     * 
     */
    public String sourceManagedListId() {
        return this.sourceManagedListId;
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
     * @return The date and time the managed list was created. Format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the managed list was last updated. Format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedListsManagedListCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private String feedProvider;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isEditable;
        private String lifecyleDetails;
        private List<String> listItems;
        private String listType;
        private String sourceManagedListId;
        private String state;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetManagedListsManagedListCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.feedProvider = defaults.feedProvider;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEditable = defaults.isEditable;
    	      this.lifecyleDetails = defaults.lifecyleDetails;
    	      this.listItems = defaults.listItems;
    	      this.listType = defaults.listType;
    	      this.sourceManagedListId = defaults.sourceManagedListId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder feedProvider(String feedProvider) {
            if (feedProvider == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "feedProvider");
            }
            this.feedProvider = feedProvider;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isEditable(Boolean isEditable) {
            if (isEditable == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "isEditable");
            }
            this.isEditable = isEditable;
            return this;
        }
        @CustomType.Setter
        public Builder lifecyleDetails(String lifecyleDetails) {
            if (lifecyleDetails == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "lifecyleDetails");
            }
            this.lifecyleDetails = lifecyleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder listItems(List<String> listItems) {
            if (listItems == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "listItems");
            }
            this.listItems = listItems;
            return this;
        }
        public Builder listItems(String... listItems) {
            return listItems(List.of(listItems));
        }
        @CustomType.Setter
        public Builder listType(String listType) {
            if (listType == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "listType");
            }
            this.listType = listType;
            return this;
        }
        @CustomType.Setter
        public Builder sourceManagedListId(String sourceManagedListId) {
            if (sourceManagedListId == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "sourceManagedListId");
            }
            this.sourceManagedListId = sourceManagedListId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetManagedListsManagedListCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetManagedListsManagedListCollectionItem build() {
            final var _resultValue = new GetManagedListsManagedListCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.feedProvider = feedProvider;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isEditable = isEditable;
            _resultValue.lifecyleDetails = lifecyleDetails;
            _resultValue.listItems = listItems;
            _resultValue.listType = listType;
            _resultValue.sourceManagedListId = sourceManagedListId;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
