// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetFleetTargetsFleetTargetCollectionItemResource;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetFleetTargetsFleetTargetCollectionItem {
    /**
     * @return Tenancy OCID
     * 
     */
    private String compartmentId;
    /**
     * @return Last known compliance state of Target.
     * 
     */
    private String complianceState;
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
     * @return Product Name
     * 
     */
    private String product;
    /**
     * @return Resource Information for the Target
     * 
     */
    private List<GetFleetTargetsFleetTargetCollectionItemResource> resources;
    /**
     * @return The current state of the FleetTarget.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return Current version of Target
     * 
     */
    private String version;

    private GetFleetTargetsFleetTargetCollectionItem() {}
    /**
     * @return Tenancy OCID
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Last known compliance state of Target.
     * 
     */
    public String complianceState() {
        return this.complianceState;
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
     * @return Product Name
     * 
     */
    public String product() {
        return this.product;
    }
    /**
     * @return Resource Information for the Target
     * 
     */
    public List<GetFleetTargetsFleetTargetCollectionItemResource> resources() {
        return this.resources;
    }
    /**
     * @return The current state of the FleetTarget.
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
     * @return Current version of Target
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetTargetsFleetTargetCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String complianceState;
        private String displayName;
        private String id;
        private String product;
        private List<GetFleetTargetsFleetTargetCollectionItemResource> resources;
        private String state;
        private Map<String,String> systemTags;
        private String version;
        public Builder() {}
        public Builder(GetFleetTargetsFleetTargetCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.complianceState = defaults.complianceState;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.product = defaults.product;
    	      this.resources = defaults.resources;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder complianceState(String complianceState) {
            if (complianceState == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "complianceState");
            }
            this.complianceState = complianceState;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder product(String product) {
            if (product == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "product");
            }
            this.product = product;
            return this;
        }
        @CustomType.Setter
        public Builder resources(List<GetFleetTargetsFleetTargetCollectionItemResource> resources) {
            if (resources == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "resources");
            }
            this.resources = resources;
            return this;
        }
        public Builder resources(GetFleetTargetsFleetTargetCollectionItemResource... resources) {
            return resources(List.of(resources));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetFleetTargetsFleetTargetCollectionItem", "version");
            }
            this.version = version;
            return this;
        }
        public GetFleetTargetsFleetTargetCollectionItem build() {
            final var _resultValue = new GetFleetTargetsFleetTargetCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.complianceState = complianceState;
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.product = product;
            _resultValue.resources = resources;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
