// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCatalogTypesTypeCollectionItem {
    /**
     * @return Unique catalog identifier.
     * 
     */
    private String catalogId;
    /**
     * @return Detailed description of the type.
     * 
     */
    private String description;
    /**
     * @return Unique type key that is immutable.
     * 
     */
    private String key;
    /**
     * @return Immutable resource name.
     * 
     */
    private String name;
    /**
     * @return A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     * 
     */
    private String state;
    /**
     * @return Indicates the category of this type . For example, data assets or connections.
     * 
     */
    private String typeCategory;
    /**
     * @return URI to the type instance in the API.
     * 
     */
    private String uri;

    private GetCatalogTypesTypeCollectionItem() {}
    /**
     * @return Unique catalog identifier.
     * 
     */
    public String catalogId() {
        return this.catalogId;
    }
    /**
     * @return Detailed description of the type.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Unique type key that is immutable.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return Immutable resource name.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Indicates the category of this type . For example, data assets or connections.
     * 
     */
    public String typeCategory() {
        return this.typeCategory;
    }
    /**
     * @return URI to the type instance in the API.
     * 
     */
    public String uri() {
        return this.uri;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCatalogTypesTypeCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String catalogId;
        private String description;
        private String key;
        private String name;
        private String state;
        private String typeCategory;
        private String uri;
        public Builder() {}
        public Builder(GetCatalogTypesTypeCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.catalogId = defaults.catalogId;
    	      this.description = defaults.description;
    	      this.key = defaults.key;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.typeCategory = defaults.typeCategory;
    	      this.uri = defaults.uri;
        }

        @CustomType.Setter
        public Builder catalogId(String catalogId) {
            this.catalogId = Objects.requireNonNull(catalogId);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder typeCategory(String typeCategory) {
            this.typeCategory = Objects.requireNonNull(typeCategory);
            return this;
        }
        @CustomType.Setter
        public Builder uri(String uri) {
            this.uri = Objects.requireNonNull(uri);
            return this;
        }
        public GetCatalogTypesTypeCollectionItem build() {
            final var o = new GetCatalogTypesTypeCollectionItem();
            o.catalogId = catalogId;
            o.description = description;
            o.key = key;
            o.name = name;
            o.state = state;
            o.typeCategory = typeCategory;
            o.uri = uri;
            return o;
        }
    }
}