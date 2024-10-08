// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CapacityManagement.outputs.GetOccAvailabilityCatalogsFilter;
import com.pulumi.oci.CapacityManagement.outputs.GetOccAvailabilityCatalogsOccAvailabilityCatalogCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetOccAvailabilityCatalogsResult {
    /**
     * @return The different states associated with the availability catalog.
     * 
     */
    private @Nullable String catalogState;
    /**
     * @return The OCID of the tenancy where the availability catalog resides.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name for the availability catalog.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetOccAvailabilityCatalogsFilter> filters;
    /**
     * @return The OCID of the availability catalog.
     * 
     */
    private @Nullable String id;
    /**
     * @return The name of the Oracle Cloud Infrastructure service in consideration. For example, Compute, Exadata, and so on.
     * 
     */
    private @Nullable String namespace;
    /**
     * @return The list of occ_availability_catalog_collection.
     * 
     */
    private List<GetOccAvailabilityCatalogsOccAvailabilityCatalogCollection> occAvailabilityCatalogCollections;

    private GetOccAvailabilityCatalogsResult() {}
    /**
     * @return The different states associated with the availability catalog.
     * 
     */
    public Optional<String> catalogState() {
        return Optional.ofNullable(this.catalogState);
    }
    /**
     * @return The OCID of the tenancy where the availability catalog resides.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name for the availability catalog.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetOccAvailabilityCatalogsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the availability catalog.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The name of the Oracle Cloud Infrastructure service in consideration. For example, Compute, Exadata, and so on.
     * 
     */
    public Optional<String> namespace() {
        return Optional.ofNullable(this.namespace);
    }
    /**
     * @return The list of occ_availability_catalog_collection.
     * 
     */
    public List<GetOccAvailabilityCatalogsOccAvailabilityCatalogCollection> occAvailabilityCatalogCollections() {
        return this.occAvailabilityCatalogCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOccAvailabilityCatalogsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String catalogState;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetOccAvailabilityCatalogsFilter> filters;
        private @Nullable String id;
        private @Nullable String namespace;
        private List<GetOccAvailabilityCatalogsOccAvailabilityCatalogCollection> occAvailabilityCatalogCollections;
        public Builder() {}
        public Builder(GetOccAvailabilityCatalogsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.catalogState = defaults.catalogState;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.namespace = defaults.namespace;
    	      this.occAvailabilityCatalogCollections = defaults.occAvailabilityCatalogCollections;
        }

        @CustomType.Setter
        public Builder catalogState(@Nullable String catalogState) {

            this.catalogState = catalogState;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetOccAvailabilityCatalogsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetOccAvailabilityCatalogsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetOccAvailabilityCatalogsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(@Nullable String namespace) {

            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder occAvailabilityCatalogCollections(List<GetOccAvailabilityCatalogsOccAvailabilityCatalogCollection> occAvailabilityCatalogCollections) {
            if (occAvailabilityCatalogCollections == null) {
              throw new MissingRequiredPropertyException("GetOccAvailabilityCatalogsResult", "occAvailabilityCatalogCollections");
            }
            this.occAvailabilityCatalogCollections = occAvailabilityCatalogCollections;
            return this;
        }
        public Builder occAvailabilityCatalogCollections(GetOccAvailabilityCatalogsOccAvailabilityCatalogCollection... occAvailabilityCatalogCollections) {
            return occAvailabilityCatalogCollections(List.of(occAvailabilityCatalogCollections));
        }
        public GetOccAvailabilityCatalogsResult build() {
            final var _resultValue = new GetOccAvailabilityCatalogsResult();
            _resultValue.catalogState = catalogState;
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.namespace = namespace;
            _resultValue.occAvailabilityCatalogCollections = occAvailabilityCatalogCollections;
            return _resultValue;
        }
    }
}
