// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetConnectionsConnectionCollectionItem {
    /**
     * @return Unique catalog identifier.
     * 
     */
    private final String catalogId;
    /**
     * @return OCID of the user who created the resource.
     * 
     */
    private final String createdById;
    /**
     * @return Unique data asset key.
     * 
     */
    private final String dataAssetKey;
    /**
     * @return A description of the connection.
     * 
     */
    private final String description;
    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    private final String displayName;
    private final @Nullable Map<String,Object> encProperties;
    /**
     * @return Unique external identifier of this resource in the external source system.
     * 
     */
    private final String externalKey;
    /**
     * @return Indicates whether this connection is the default connection.
     * 
     */
    private final Boolean isDefault;
    /**
     * @return Unique connection key that is immutable.
     * 
     */
    private final String key;
    /**
     * @return A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it&#39;s set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the &#34;default&#34; category. Example: `{&#34;properties&#34;: { &#34;default&#34;: { &#34;username&#34;: &#34;user1&#34;}}}`
     * 
     */
    private final Map<String,Object> properties;
    /**
     * @return A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     * 
     */
    private final String state;
    /**
     * @return Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    private final String timeCreated;
    /**
     * @return Time that the resource&#39;s status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    private final String timeStatusUpdated;
    /**
     * @return Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    private final String timeUpdated;
    /**
     * @return The key of the object type. Type key&#39;s can be found via the &#39;/types&#39; endpoint.
     * 
     */
    private final String typeKey;
    /**
     * @return OCID of the user who updated the resource.
     * 
     */
    private final String updatedById;
    /**
     * @return URI to the connection instance in the API.
     * 
     */
    private final String uri;

    @CustomType.Constructor
    private GetConnectionsConnectionCollectionItem(
        @CustomType.Parameter("catalogId") String catalogId,
        @CustomType.Parameter("createdById") String createdById,
        @CustomType.Parameter("dataAssetKey") String dataAssetKey,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("encProperties") @Nullable Map<String,Object> encProperties,
        @CustomType.Parameter("externalKey") String externalKey,
        @CustomType.Parameter("isDefault") Boolean isDefault,
        @CustomType.Parameter("key") String key,
        @CustomType.Parameter("properties") Map<String,Object> properties,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeStatusUpdated") String timeStatusUpdated,
        @CustomType.Parameter("timeUpdated") String timeUpdated,
        @CustomType.Parameter("typeKey") String typeKey,
        @CustomType.Parameter("updatedById") String updatedById,
        @CustomType.Parameter("uri") String uri) {
        this.catalogId = catalogId;
        this.createdById = createdById;
        this.dataAssetKey = dataAssetKey;
        this.description = description;
        this.displayName = displayName;
        this.encProperties = encProperties;
        this.externalKey = externalKey;
        this.isDefault = isDefault;
        this.key = key;
        this.properties = properties;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeStatusUpdated = timeStatusUpdated;
        this.timeUpdated = timeUpdated;
        this.typeKey = typeKey;
        this.updatedById = updatedById;
        this.uri = uri;
    }

    /**
     * @return Unique catalog identifier.
     * 
     */
    public String catalogId() {
        return this.catalogId;
    }
    /**
     * @return OCID of the user who created the resource.
     * 
     */
    public String createdById() {
        return this.createdById;
    }
    /**
     * @return Unique data asset key.
     * 
     */
    public String dataAssetKey() {
        return this.dataAssetKey;
    }
    /**
     * @return A description of the connection.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only resources that match the entire display name given. The match is not case sensitive.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    public Map<String,Object> encProperties() {
        return this.encProperties == null ? Map.of() : this.encProperties;
    }
    /**
     * @return Unique external identifier of this resource in the external source system.
     * 
     */
    public String externalKey() {
        return this.externalKey;
    }
    /**
     * @return Indicates whether this connection is the default connection.
     * 
     */
    public Boolean isDefault() {
        return this.isDefault;
    }
    /**
     * @return Unique connection key that is immutable.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it&#39;s set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the &#34;default&#34; category. Example: `{&#34;properties&#34;: { &#34;default&#34;: { &#34;username&#34;: &#34;user1&#34;}}}`
     * 
     */
    public Map<String,Object> properties() {
        return this.properties;
    }
    /**
     * @return A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Time that the resource&#39;s status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    public String timeStatusUpdated() {
        return this.timeStatusUpdated;
    }
    /**
     * @return Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The key of the object type. Type key&#39;s can be found via the &#39;/types&#39; endpoint.
     * 
     */
    public String typeKey() {
        return this.typeKey;
    }
    /**
     * @return OCID of the user who updated the resource.
     * 
     */
    public String updatedById() {
        return this.updatedById;
    }
    /**
     * @return URI to the connection instance in the API.
     * 
     */
    public String uri() {
        return this.uri;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConnectionsConnectionCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String catalogId;
        private String createdById;
        private String dataAssetKey;
        private String description;
        private String displayName;
        private @Nullable Map<String,Object> encProperties;
        private String externalKey;
        private Boolean isDefault;
        private String key;
        private Map<String,Object> properties;
        private String state;
        private String timeCreated;
        private String timeStatusUpdated;
        private String timeUpdated;
        private String typeKey;
        private String updatedById;
        private String uri;

        public Builder() {
    	      // Empty
        }

        public Builder(GetConnectionsConnectionCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.catalogId = defaults.catalogId;
    	      this.createdById = defaults.createdById;
    	      this.dataAssetKey = defaults.dataAssetKey;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.encProperties = defaults.encProperties;
    	      this.externalKey = defaults.externalKey;
    	      this.isDefault = defaults.isDefault;
    	      this.key = defaults.key;
    	      this.properties = defaults.properties;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeStatusUpdated = defaults.timeStatusUpdated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.typeKey = defaults.typeKey;
    	      this.updatedById = defaults.updatedById;
    	      this.uri = defaults.uri;
        }

        public Builder catalogId(String catalogId) {
            this.catalogId = Objects.requireNonNull(catalogId);
            return this;
        }
        public Builder createdById(String createdById) {
            this.createdById = Objects.requireNonNull(createdById);
            return this;
        }
        public Builder dataAssetKey(String dataAssetKey) {
            this.dataAssetKey = Objects.requireNonNull(dataAssetKey);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder encProperties(@Nullable Map<String,Object> encProperties) {
            this.encProperties = encProperties;
            return this;
        }
        public Builder externalKey(String externalKey) {
            this.externalKey = Objects.requireNonNull(externalKey);
            return this;
        }
        public Builder isDefault(Boolean isDefault) {
            this.isDefault = Objects.requireNonNull(isDefault);
            return this;
        }
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        public Builder properties(Map<String,Object> properties) {
            this.properties = Objects.requireNonNull(properties);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeStatusUpdated(String timeStatusUpdated) {
            this.timeStatusUpdated = Objects.requireNonNull(timeStatusUpdated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public Builder typeKey(String typeKey) {
            this.typeKey = Objects.requireNonNull(typeKey);
            return this;
        }
        public Builder updatedById(String updatedById) {
            this.updatedById = Objects.requireNonNull(updatedById);
            return this;
        }
        public Builder uri(String uri) {
            this.uri = Objects.requireNonNull(uri);
            return this;
        }        public GetConnectionsConnectionCollectionItem build() {
            return new GetConnectionsConnectionCollectionItem(catalogId, createdById, dataAssetKey, description, displayName, encProperties, externalKey, isDefault, key, properties, state, timeCreated, timeStatusUpdated, timeUpdated, typeKey, updatedById, uri);
        }
    }
}
