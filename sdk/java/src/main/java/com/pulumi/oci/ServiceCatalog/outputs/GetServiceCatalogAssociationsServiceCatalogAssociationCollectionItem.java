// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItem {
    /**
     * @return The unique identifier of the entity associated with service catalog.
     * 
     */
    private String entityId;
    /**
     * @return The type of the application in the service catalog.
     * 
     */
    private String entityType;
    /**
     * @return Identifier of the association.
     * 
     */
    private String id;
    /**
     * @return The unique identifier for the service catalog.
     * 
     */
    private String serviceCatalogId;
    /**
     * @return Timestamp of when the resource was associated with service catalog.
     * 
     */
    private String timeCreated;

    private GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItem() {}
    /**
     * @return The unique identifier of the entity associated with service catalog.
     * 
     */
    public String entityId() {
        return this.entityId;
    }
    /**
     * @return The type of the application in the service catalog.
     * 
     */
    public String entityType() {
        return this.entityType;
    }
    /**
     * @return Identifier of the association.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The unique identifier for the service catalog.
     * 
     */
    public String serviceCatalogId() {
        return this.serviceCatalogId;
    }
    /**
     * @return Timestamp of when the resource was associated with service catalog.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String entityId;
        private String entityType;
        private String id;
        private String serviceCatalogId;
        private String timeCreated;
        public Builder() {}
        public Builder(GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.entityId = defaults.entityId;
    	      this.entityType = defaults.entityType;
    	      this.id = defaults.id;
    	      this.serviceCatalogId = defaults.serviceCatalogId;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder entityId(String entityId) {
            this.entityId = Objects.requireNonNull(entityId);
            return this;
        }
        @CustomType.Setter
        public Builder entityType(String entityType) {
            this.entityType = Objects.requireNonNull(entityType);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder serviceCatalogId(String serviceCatalogId) {
            this.serviceCatalogId = Objects.requireNonNull(serviceCatalogId);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItem build() {
            final var o = new GetServiceCatalogAssociationsServiceCatalogAssociationCollectionItem();
            o.entityId = entityId;
            o.entityType = entityType;
            o.id = id;
            o.serviceCatalogId = serviceCatalogId;
            o.timeCreated = timeCreated;
            return o;
        }
    }
}