// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem {
    /**
     * @return The OCID of the resource.
     * 
     */
    private String compartmentId;
    /**
     * @return Count of Resources affected by the Schedule
     * 
     */
    private Integer countOfAffectedResources;
    /**
     * @return Count of Targets affected by the Schedule
     * 
     */
    private Integer countOfAffectedTargets;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return The OCID of the resource.
     * 
     */
    private String id;
    /**
     * @return All products part of the schedule.
     * 
     */
    private List<String> products;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;

    private GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem() {}
    /**
     * @return The OCID of the resource.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Count of Resources affected by the Schedule
     * 
     */
    public Integer countOfAffectedResources() {
        return this.countOfAffectedResources;
    }
    /**
     * @return Count of Targets affected by the Schedule
     * 
     */
    public Integer countOfAffectedTargets() {
        return this.countOfAffectedTargets;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The OCID of the resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return All products part of the schedule.
     * 
     */
    public List<String> products() {
        return this.products;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Integer countOfAffectedResources;
        private Integer countOfAffectedTargets;
        private String displayName;
        private String id;
        private List<String> products;
        private Map<String,String> systemTags;
        public Builder() {}
        public Builder(GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.countOfAffectedResources = defaults.countOfAffectedResources;
    	      this.countOfAffectedTargets = defaults.countOfAffectedTargets;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.products = defaults.products;
    	      this.systemTags = defaults.systemTags;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder countOfAffectedResources(Integer countOfAffectedResources) {
            if (countOfAffectedResources == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem", "countOfAffectedResources");
            }
            this.countOfAffectedResources = countOfAffectedResources;
            return this;
        }
        @CustomType.Setter
        public Builder countOfAffectedTargets(Integer countOfAffectedTargets) {
            if (countOfAffectedTargets == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem", "countOfAffectedTargets");
            }
            this.countOfAffectedTargets = countOfAffectedTargets;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder products(List<String> products) {
            if (products == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem", "products");
            }
            this.products = products;
            return this;
        }
        public Builder products(String... products) {
            return products(List.of(products));
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        public GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem build() {
            final var _resultValue = new GetSchedulerDefinitionScheduledFleetsScheduledFleetCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.countOfAffectedResources = countOfAffectedResources;
            _resultValue.countOfAffectedTargets = countOfAffectedTargets;
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.products = products;
            _resultValue.systemTags = systemTags;
            return _resultValue;
        }
    }
}
