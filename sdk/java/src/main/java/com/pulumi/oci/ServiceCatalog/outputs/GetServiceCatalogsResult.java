// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ServiceCatalog.outputs.GetServiceCatalogsFilter;
import com.pulumi.oci.ServiceCatalog.outputs.GetServiceCatalogsServiceCatalogCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetServiceCatalogsResult {
    /**
     * @return The Compartment id where the service catalog exists
     * 
     */
    private String compartmentId;
    /**
     * @return The name of the service catalog.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetServiceCatalogsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of service_catalog_collection.
     * 
     */
    private List<GetServiceCatalogsServiceCatalogCollection> serviceCatalogCollections;
    private @Nullable String serviceCatalogId;

    private GetServiceCatalogsResult() {}
    /**
     * @return The Compartment id where the service catalog exists
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The name of the service catalog.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetServiceCatalogsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of service_catalog_collection.
     * 
     */
    public List<GetServiceCatalogsServiceCatalogCollection> serviceCatalogCollections() {
        return this.serviceCatalogCollections;
    }
    public Optional<String> serviceCatalogId() {
        return Optional.ofNullable(this.serviceCatalogId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceCatalogsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetServiceCatalogsFilter> filters;
        private String id;
        private List<GetServiceCatalogsServiceCatalogCollection> serviceCatalogCollections;
        private @Nullable String serviceCatalogId;
        public Builder() {}
        public Builder(GetServiceCatalogsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.serviceCatalogCollections = defaults.serviceCatalogCollections;
    	      this.serviceCatalogId = defaults.serviceCatalogId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetServiceCatalogsResult", "compartmentId");
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
        public Builder filters(@Nullable List<GetServiceCatalogsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetServiceCatalogsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetServiceCatalogsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder serviceCatalogCollections(List<GetServiceCatalogsServiceCatalogCollection> serviceCatalogCollections) {
            if (serviceCatalogCollections == null) {
              throw new MissingRequiredPropertyException("GetServiceCatalogsResult", "serviceCatalogCollections");
            }
            this.serviceCatalogCollections = serviceCatalogCollections;
            return this;
        }
        public Builder serviceCatalogCollections(GetServiceCatalogsServiceCatalogCollection... serviceCatalogCollections) {
            return serviceCatalogCollections(List.of(serviceCatalogCollections));
        }
        @CustomType.Setter
        public Builder serviceCatalogId(@Nullable String serviceCatalogId) {

            this.serviceCatalogId = serviceCatalogId;
            return this;
        }
        public GetServiceCatalogsResult build() {
            final var _resultValue = new GetServiceCatalogsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.serviceCatalogCollections = serviceCatalogCollections;
            _resultValue.serviceCatalogId = serviceCatalogId;
            return _resultValue;
        }
    }
}
