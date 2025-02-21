// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetInventoryResourcesFilter;
import com.pulumi.oci.FleetAppsManagement.outputs.GetInventoryResourcesInventoryResourceCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetInventoryResourcesResult {
    /**
     * @return OCID of the compartment to which the resource belongs to.
     * 
     */
    private String compartmentId;
    private @Nullable List<String> definedTagEquals;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetInventoryResourcesFilter> filters;
    private @Nullable List<String> freeformTagEquals;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable List<String> inventoryProperties;
    /**
     * @return The list of inventory_resource_collection.
     * 
     */
    private List<GetInventoryResourcesInventoryResourceCollection> inventoryResourceCollections;
    private @Nullable String matchingCriteria;
    /**
     * @return Compartment Id of the resource.
     * 
     */
    private String resourceCompartmentId;
    /**
     * @return The region the resource belongs to.
     * 
     */
    private @Nullable String resourceRegion;
    /**
     * @return The current state of the Resource.
     * 
     */
    private @Nullable String state;

    private GetInventoryResourcesResult() {}
    /**
     * @return OCID of the compartment to which the resource belongs to.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<String> definedTagEquals() {
        return this.definedTagEquals == null ? List.of() : this.definedTagEquals;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetInventoryResourcesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    public List<String> freeformTagEquals() {
        return this.freeformTagEquals == null ? List.of() : this.freeformTagEquals;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public List<String> inventoryProperties() {
        return this.inventoryProperties == null ? List.of() : this.inventoryProperties;
    }
    /**
     * @return The list of inventory_resource_collection.
     * 
     */
    public List<GetInventoryResourcesInventoryResourceCollection> inventoryResourceCollections() {
        return this.inventoryResourceCollections;
    }
    public Optional<String> matchingCriteria() {
        return Optional.ofNullable(this.matchingCriteria);
    }
    /**
     * @return Compartment Id of the resource.
     * 
     */
    public String resourceCompartmentId() {
        return this.resourceCompartmentId;
    }
    /**
     * @return The region the resource belongs to.
     * 
     */
    public Optional<String> resourceRegion() {
        return Optional.ofNullable(this.resourceRegion);
    }
    /**
     * @return The current state of the Resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInventoryResourcesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<String> definedTagEquals;
        private @Nullable String displayName;
        private @Nullable List<GetInventoryResourcesFilter> filters;
        private @Nullable List<String> freeformTagEquals;
        private String id;
        private @Nullable List<String> inventoryProperties;
        private List<GetInventoryResourcesInventoryResourceCollection> inventoryResourceCollections;
        private @Nullable String matchingCriteria;
        private String resourceCompartmentId;
        private @Nullable String resourceRegion;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetInventoryResourcesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTagEquals = defaults.definedTagEquals;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.freeformTagEquals = defaults.freeformTagEquals;
    	      this.id = defaults.id;
    	      this.inventoryProperties = defaults.inventoryProperties;
    	      this.inventoryResourceCollections = defaults.inventoryResourceCollections;
    	      this.matchingCriteria = defaults.matchingCriteria;
    	      this.resourceCompartmentId = defaults.resourceCompartmentId;
    	      this.resourceRegion = defaults.resourceRegion;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetInventoryResourcesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTagEquals(@Nullable List<String> definedTagEquals) {

            this.definedTagEquals = definedTagEquals;
            return this;
        }
        public Builder definedTagEquals(String... definedTagEquals) {
            return definedTagEquals(List.of(definedTagEquals));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetInventoryResourcesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetInventoryResourcesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder freeformTagEquals(@Nullable List<String> freeformTagEquals) {

            this.freeformTagEquals = freeformTagEquals;
            return this;
        }
        public Builder freeformTagEquals(String... freeformTagEquals) {
            return freeformTagEquals(List.of(freeformTagEquals));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetInventoryResourcesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder inventoryProperties(@Nullable List<String> inventoryProperties) {

            this.inventoryProperties = inventoryProperties;
            return this;
        }
        public Builder inventoryProperties(String... inventoryProperties) {
            return inventoryProperties(List.of(inventoryProperties));
        }
        @CustomType.Setter
        public Builder inventoryResourceCollections(List<GetInventoryResourcesInventoryResourceCollection> inventoryResourceCollections) {
            if (inventoryResourceCollections == null) {
              throw new MissingRequiredPropertyException("GetInventoryResourcesResult", "inventoryResourceCollections");
            }
            this.inventoryResourceCollections = inventoryResourceCollections;
            return this;
        }
        public Builder inventoryResourceCollections(GetInventoryResourcesInventoryResourceCollection... inventoryResourceCollections) {
            return inventoryResourceCollections(List.of(inventoryResourceCollections));
        }
        @CustomType.Setter
        public Builder matchingCriteria(@Nullable String matchingCriteria) {

            this.matchingCriteria = matchingCriteria;
            return this;
        }
        @CustomType.Setter
        public Builder resourceCompartmentId(String resourceCompartmentId) {
            if (resourceCompartmentId == null) {
              throw new MissingRequiredPropertyException("GetInventoryResourcesResult", "resourceCompartmentId");
            }
            this.resourceCompartmentId = resourceCompartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder resourceRegion(@Nullable String resourceRegion) {

            this.resourceRegion = resourceRegion;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetInventoryResourcesResult build() {
            final var _resultValue = new GetInventoryResourcesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTagEquals = definedTagEquals;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.freeformTagEquals = freeformTagEquals;
            _resultValue.id = id;
            _resultValue.inventoryProperties = inventoryProperties;
            _resultValue.inventoryResourceCollections = inventoryResourceCollections;
            _resultValue.matchingCriteria = matchingCriteria;
            _resultValue.resourceCompartmentId = resourceCompartmentId;
            _resultValue.resourceRegion = resourceRegion;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
