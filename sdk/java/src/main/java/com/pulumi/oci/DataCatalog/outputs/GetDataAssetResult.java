// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetDataAssetResult {
    /**
     * @return The data catalog&#39;s OCID.
     * 
     */
    private final String catalogId;
    /**
     * @return OCID of the user who created the data asset.
     * 
     */
    private final String createdById;
    private final String dataAssetKey;
    /**
     * @return Detailed description of the data asset.
     * 
     */
    private final String description;
    /**
     * @return A user-friendly display name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private final String displayName;
    /**
     * @return External URI that can be used to reference the object. Format will differ based on the type of object.
     * 
     */
    private final String externalKey;
    private final @Nullable List<String> fields;
    private final String id;
    /**
     * @return Unique data asset key that is immutable.
     * 
     */
    private final String key;
    /**
     * @return A map of maps that contains the properties which are specific to the asset type. Each data asset type definition defines it&#39;s set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most data assets have required properties within the &#34;default&#34; category. Example: `{&#34;properties&#34;: { &#34;default&#34;: { &#34;host&#34;: &#34;host1&#34;, &#34;port&#34;: &#34;1521&#34;, &#34;database&#34;: &#34;orcl&#34;}}}`
     * 
     */
    private final Map<String,Object> properties;
    /**
     * @return The current state of the data asset.
     * 
     */
    private final String state;
    /**
     * @return The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The last time that a harvest was performed on the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    private final String timeHarvested;
    /**
     * @return The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    private final String timeUpdated;
    /**
     * @return The key of the object type. Type key&#39;s can be found via the &#39;/types&#39; endpoint.
     * 
     */
    private final String typeKey;
    /**
     * @return OCID of the user who last modified the data asset.
     * 
     */
    private final String updatedById;
    /**
     * @return URI to the data asset instance in the API.
     * 
     */
    private final String uri;

    @CustomType.Constructor
    private GetDataAssetResult(
        @CustomType.Parameter("catalogId") String catalogId,
        @CustomType.Parameter("createdById") String createdById,
        @CustomType.Parameter("dataAssetKey") String dataAssetKey,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("externalKey") String externalKey,
        @CustomType.Parameter("fields") @Nullable List<String> fields,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("key") String key,
        @CustomType.Parameter("properties") Map<String,Object> properties,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeHarvested") String timeHarvested,
        @CustomType.Parameter("timeUpdated") String timeUpdated,
        @CustomType.Parameter("typeKey") String typeKey,
        @CustomType.Parameter("updatedById") String updatedById,
        @CustomType.Parameter("uri") String uri) {
        this.catalogId = catalogId;
        this.createdById = createdById;
        this.dataAssetKey = dataAssetKey;
        this.description = description;
        this.displayName = displayName;
        this.externalKey = externalKey;
        this.fields = fields;
        this.id = id;
        this.key = key;
        this.properties = properties;
        this.state = state;
        this.timeCreated = timeCreated;
        this.timeHarvested = timeHarvested;
        this.timeUpdated = timeUpdated;
        this.typeKey = typeKey;
        this.updatedById = updatedById;
        this.uri = uri;
    }

    /**
     * @return The data catalog&#39;s OCID.
     * 
     */
    public String catalogId() {
        return this.catalogId;
    }
    /**
     * @return OCID of the user who created the data asset.
     * 
     */
    public String createdById() {
        return this.createdById;
    }
    public String dataAssetKey() {
        return this.dataAssetKey;
    }
    /**
     * @return Detailed description of the data asset.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly display name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return External URI that can be used to reference the object. Format will differ based on the type of object.
     * 
     */
    public String externalKey() {
        return this.externalKey;
    }
    public List<String> fields() {
        return this.fields == null ? List.of() : this.fields;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return Unique data asset key that is immutable.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return A map of maps that contains the properties which are specific to the asset type. Each data asset type definition defines it&#39;s set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most data assets have required properties within the &#34;default&#34; category. Example: `{&#34;properties&#34;: { &#34;default&#34;: { &#34;host&#34;: &#34;host1&#34;, &#34;port&#34;: &#34;1521&#34;, &#34;database&#34;: &#34;orcl&#34;}}}`
     * 
     */
    public Map<String,Object> properties() {
        return this.properties;
    }
    /**
     * @return The current state of the data asset.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The last time that a harvest was performed on the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
     * 
     */
    public String timeHarvested() {
        return this.timeHarvested;
    }
    /**
     * @return The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
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
     * @return OCID of the user who last modified the data asset.
     * 
     */
    public String updatedById() {
        return this.updatedById;
    }
    /**
     * @return URI to the data asset instance in the API.
     * 
     */
    public String uri() {
        return this.uri;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDataAssetResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String catalogId;
        private String createdById;
        private String dataAssetKey;
        private String description;
        private String displayName;
        private String externalKey;
        private @Nullable List<String> fields;
        private String id;
        private String key;
        private Map<String,Object> properties;
        private String state;
        private String timeCreated;
        private String timeHarvested;
        private String timeUpdated;
        private String typeKey;
        private String updatedById;
        private String uri;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDataAssetResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.catalogId = defaults.catalogId;
    	      this.createdById = defaults.createdById;
    	      this.dataAssetKey = defaults.dataAssetKey;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.externalKey = defaults.externalKey;
    	      this.fields = defaults.fields;
    	      this.id = defaults.id;
    	      this.key = defaults.key;
    	      this.properties = defaults.properties;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeHarvested = defaults.timeHarvested;
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
        public Builder externalKey(String externalKey) {
            this.externalKey = Objects.requireNonNull(externalKey);
            return this;
        }
        public Builder fields(@Nullable List<String> fields) {
            this.fields = fields;
            return this;
        }
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
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
        public Builder timeHarvested(String timeHarvested) {
            this.timeHarvested = Objects.requireNonNull(timeHarvested);
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
        }        public GetDataAssetResult build() {
            return new GetDataAssetResult(catalogId, createdById, dataAssetKey, description, displayName, externalKey, fields, id, key, properties, state, timeCreated, timeHarvested, timeUpdated, typeKey, updatedById, uri);
        }
    }
}
