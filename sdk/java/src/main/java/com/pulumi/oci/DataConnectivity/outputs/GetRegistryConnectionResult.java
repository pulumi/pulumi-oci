// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataConnectivity.outputs.GetRegistryConnectionConnectionProperty;
import com.pulumi.oci.DataConnectivity.outputs.GetRegistryConnectionMetadata;
import com.pulumi.oci.DataConnectivity.outputs.GetRegistryConnectionPrimarySchema;
import com.pulumi.oci.DataConnectivity.outputs.GetRegistryConnectionRegistryMetadata;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetRegistryConnectionResult {
    private String connectionKey;
    /**
     * @return The properties of the connection.
     * 
     */
    private List<GetRegistryConnectionConnectionProperty> connectionProperties;
    /**
     * @return The description of the aggregator.
     * 
     */
    private String description;
    private String id;
    /**
     * @return The identifier of the aggregator.
     * 
     */
    private String identifier;
    /**
     * @return The default property of the connection.
     * 
     */
    private Boolean isDefault;
    /**
     * @return The identifying key for the object.
     * 
     */
    private String key;
    /**
     * @return A summary type containing information about the object including its key, name, the time that it was created or updated, and the user who created or updated it.
     * 
     */
    private List<GetRegistryConnectionMetadata> metadatas;
    /**
     * @return The object type.
     * 
     */
    private String modelType;
    /**
     * @return The model version of the object.
     * 
     */
    private String modelVersion;
    /**
     * @return Free form text without any restriction on the permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    private String name;
    /**
     * @return The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    private Integer objectStatus;
    /**
     * @return The version of the object that is used to track changes in the object instance.
     * 
     */
    private Integer objectVersion;
    /**
     * @return The schema object.
     * 
     */
    private List<GetRegistryConnectionPrimarySchema> primarySchemas;
    /**
     * @return All the properties of the connection in a key-value map format.
     * 
     */
    private Map<String,Object> properties;
    private String registryId;
    /**
     * @return Information about the object and its parent.
     * 
     */
    private List<GetRegistryConnectionRegistryMetadata> registryMetadatas;
    /**
     * @return Specific Connection Type
     * 
     */
    private String type;

    private GetRegistryConnectionResult() {}
    public String connectionKey() {
        return this.connectionKey;
    }
    /**
     * @return The properties of the connection.
     * 
     */
    public List<GetRegistryConnectionConnectionProperty> connectionProperties() {
        return this.connectionProperties;
    }
    /**
     * @return The description of the aggregator.
     * 
     */
    public String description() {
        return this.description;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return The identifier of the aggregator.
     * 
     */
    public String identifier() {
        return this.identifier;
    }
    /**
     * @return The default property of the connection.
     * 
     */
    public Boolean isDefault() {
        return this.isDefault;
    }
    /**
     * @return The identifying key for the object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return A summary type containing information about the object including its key, name, the time that it was created or updated, and the user who created or updated it.
     * 
     */
    public List<GetRegistryConnectionMetadata> metadatas() {
        return this.metadatas;
    }
    /**
     * @return The object type.
     * 
     */
    public String modelType() {
        return this.modelType;
    }
    /**
     * @return The model version of the object.
     * 
     */
    public String modelVersion() {
        return this.modelVersion;
    }
    /**
     * @return Free form text without any restriction on the permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    public Integer objectStatus() {
        return this.objectStatus;
    }
    /**
     * @return The version of the object that is used to track changes in the object instance.
     * 
     */
    public Integer objectVersion() {
        return this.objectVersion;
    }
    /**
     * @return The schema object.
     * 
     */
    public List<GetRegistryConnectionPrimarySchema> primarySchemas() {
        return this.primarySchemas;
    }
    /**
     * @return All the properties of the connection in a key-value map format.
     * 
     */
    public Map<String,Object> properties() {
        return this.properties;
    }
    public String registryId() {
        return this.registryId;
    }
    /**
     * @return Information about the object and its parent.
     * 
     */
    public List<GetRegistryConnectionRegistryMetadata> registryMetadatas() {
        return this.registryMetadatas;
    }
    /**
     * @return Specific Connection Type
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRegistryConnectionResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String connectionKey;
        private List<GetRegistryConnectionConnectionProperty> connectionProperties;
        private String description;
        private String id;
        private String identifier;
        private Boolean isDefault;
        private String key;
        private List<GetRegistryConnectionMetadata> metadatas;
        private String modelType;
        private String modelVersion;
        private String name;
        private Integer objectStatus;
        private Integer objectVersion;
        private List<GetRegistryConnectionPrimarySchema> primarySchemas;
        private Map<String,Object> properties;
        private String registryId;
        private List<GetRegistryConnectionRegistryMetadata> registryMetadatas;
        private String type;
        public Builder() {}
        public Builder(GetRegistryConnectionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectionKey = defaults.connectionKey;
    	      this.connectionProperties = defaults.connectionProperties;
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.identifier = defaults.identifier;
    	      this.isDefault = defaults.isDefault;
    	      this.key = defaults.key;
    	      this.metadatas = defaults.metadatas;
    	      this.modelType = defaults.modelType;
    	      this.modelVersion = defaults.modelVersion;
    	      this.name = defaults.name;
    	      this.objectStatus = defaults.objectStatus;
    	      this.objectVersion = defaults.objectVersion;
    	      this.primarySchemas = defaults.primarySchemas;
    	      this.properties = defaults.properties;
    	      this.registryId = defaults.registryId;
    	      this.registryMetadatas = defaults.registryMetadatas;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder connectionKey(String connectionKey) {
            this.connectionKey = Objects.requireNonNull(connectionKey);
            return this;
        }
        @CustomType.Setter
        public Builder connectionProperties(List<GetRegistryConnectionConnectionProperty> connectionProperties) {
            this.connectionProperties = Objects.requireNonNull(connectionProperties);
            return this;
        }
        public Builder connectionProperties(GetRegistryConnectionConnectionProperty... connectionProperties) {
            return connectionProperties(List.of(connectionProperties));
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            this.identifier = Objects.requireNonNull(identifier);
            return this;
        }
        @CustomType.Setter
        public Builder isDefault(Boolean isDefault) {
            this.isDefault = Objects.requireNonNull(isDefault);
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        @CustomType.Setter
        public Builder metadatas(List<GetRegistryConnectionMetadata> metadatas) {
            this.metadatas = Objects.requireNonNull(metadatas);
            return this;
        }
        public Builder metadatas(GetRegistryConnectionMetadata... metadatas) {
            return metadatas(List.of(metadatas));
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            this.modelType = Objects.requireNonNull(modelType);
            return this;
        }
        @CustomType.Setter
        public Builder modelVersion(String modelVersion) {
            this.modelVersion = Objects.requireNonNull(modelVersion);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder objectStatus(Integer objectStatus) {
            this.objectStatus = Objects.requireNonNull(objectStatus);
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(Integer objectVersion) {
            this.objectVersion = Objects.requireNonNull(objectVersion);
            return this;
        }
        @CustomType.Setter
        public Builder primarySchemas(List<GetRegistryConnectionPrimarySchema> primarySchemas) {
            this.primarySchemas = Objects.requireNonNull(primarySchemas);
            return this;
        }
        public Builder primarySchemas(GetRegistryConnectionPrimarySchema... primarySchemas) {
            return primarySchemas(List.of(primarySchemas));
        }
        @CustomType.Setter
        public Builder properties(Map<String,Object> properties) {
            this.properties = Objects.requireNonNull(properties);
            return this;
        }
        @CustomType.Setter
        public Builder registryId(String registryId) {
            this.registryId = Objects.requireNonNull(registryId);
            return this;
        }
        @CustomType.Setter
        public Builder registryMetadatas(List<GetRegistryConnectionRegistryMetadata> registryMetadatas) {
            this.registryMetadatas = Objects.requireNonNull(registryMetadatas);
            return this;
        }
        public Builder registryMetadatas(GetRegistryConnectionRegistryMetadata... registryMetadatas) {
            return registryMetadatas(List.of(registryMetadatas));
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetRegistryConnectionResult build() {
            final var o = new GetRegistryConnectionResult();
            o.connectionKey = connectionKey;
            o.connectionProperties = connectionProperties;
            o.description = description;
            o.id = id;
            o.identifier = identifier;
            o.isDefault = isDefault;
            o.key = key;
            o.metadatas = metadatas;
            o.modelType = modelType;
            o.modelVersion = modelVersion;
            o.name = name;
            o.objectStatus = objectStatus;
            o.objectVersion = objectVersion;
            o.primarySchemas = primarySchemas;
            o.properties = properties;
            o.registryId = registryId;
            o.registryMetadatas = registryMetadatas;
            o.type = type;
            return o;
        }
    }
}