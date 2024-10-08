// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.outputs.GetOccCustomerGroupsOccCustomerGroupCollectionItemCustomersList;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetOccCustomerGroupsOccCustomerGroupCollectionItem {
    /**
     * @return The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     * 
     */
    private String compartmentId;
    /**
     * @return A list containing all the customers that belong to this customer group
     * 
     */
    private List<GetOccCustomerGroupsOccCustomerGroupCollectionItemCustomersList> customersLists;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description about the customer group.
     * 
     */
    private String description;
    /**
     * @return A filter to return only the resources that match the entire display name. The match is not case sensitive.
     * 
     */
    private String displayName;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return A query filter to return the list result based on the customer group OCID. This is done for users who have INSPECT permission but do not have READ permission.
     * 
     */
    private String id;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The current lifecycle state of the resource.
     * 
     */
    private String state;
    /**
     * @return A query filter to return the list result based on status.
     * 
     */
    private String status;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time when the customer group was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The time when the customer group was last updated.
     * 
     */
    private String timeUpdated;

    private GetOccCustomerGroupsOccCustomerGroupCollectionItem() {}
    /**
     * @return The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A list containing all the customers that belong to this customer group
     * 
     */
    public List<GetOccCustomerGroupsOccCustomerGroupCollectionItemCustomersList> customersLists() {
        return this.customersLists;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description about the customer group.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only the resources that match the entire display name. The match is not case sensitive.
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
     * @return A query filter to return the list result based on the customer group OCID. This is done for users who have INSPECT permission but do not have READ permission.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The current lifecycle state of the resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return A query filter to return the list result based on status.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time when the customer group was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time when the customer group was last updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOccCustomerGroupsOccCustomerGroupCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetOccCustomerGroupsOccCustomerGroupCollectionItemCustomersList> customersLists;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String state;
        private String status;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetOccCustomerGroupsOccCustomerGroupCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.customersLists = defaults.customersLists;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder customersLists(List<GetOccCustomerGroupsOccCustomerGroupCollectionItemCustomersList> customersLists) {
            if (customersLists == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "customersLists");
            }
            this.customersLists = customersLists;
            return this;
        }
        public Builder customersLists(GetOccCustomerGroupsOccCustomerGroupCollectionItemCustomersList... customersLists) {
            return customersLists(List.of(customersLists));
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetOccCustomerGroupsOccCustomerGroupCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetOccCustomerGroupsOccCustomerGroupCollectionItem build() {
            final var _resultValue = new GetOccCustomerGroupsOccCustomerGroupCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.customersLists = customersLists;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.state = state;
            _resultValue.status = status;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
