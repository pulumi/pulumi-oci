// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataConnectivity.inputs.RegistryDataAssetDefaultConnectionConnectionPropertyArgs;
import com.pulumi.oci.DataConnectivity.inputs.RegistryDataAssetDefaultConnectionMetadataArgs;
import com.pulumi.oci.DataConnectivity.inputs.RegistryDataAssetDefaultConnectionPrimarySchemaArgs;
import com.pulumi.oci.DataConnectivity.inputs.RegistryDataAssetDefaultConnectionRegistryMetadataArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RegistryDataAssetDefaultConnectionArgs extends com.pulumi.resources.ResourceArgs {

    public static final RegistryDataAssetDefaultConnectionArgs Empty = new RegistryDataAssetDefaultConnectionArgs();

    /**
     * (Updatable) The properties of the connection.
     * 
     */
    @Import(name="connectionProperties")
    private @Nullable Output<List<RegistryDataAssetDefaultConnectionConnectionPropertyArgs>> connectionProperties;

    /**
     * @return (Updatable) The properties of the connection.
     * 
     */
    public Optional<Output<List<RegistryDataAssetDefaultConnectionConnectionPropertyArgs>>> connectionProperties() {
        return Optional.ofNullable(this.connectionProperties);
    }

    /**
     * (Updatable) A user-defined description for the object.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-defined description for the object.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with an upper case letter or underscore. The value can be modified.
     * 
     */
    @Import(name="identifier", required=true)
    private Output<String> identifier;

    /**
     * @return (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with an upper case letter or underscore. The value can be modified.
     * 
     */
    public Output<String> identifier() {
        return this.identifier;
    }

    /**
     * (Updatable) The default property of the connection.
     * 
     */
    @Import(name="isDefault")
    private @Nullable Output<Boolean> isDefault;

    /**
     * @return (Updatable) The default property of the connection.
     * 
     */
    public Optional<Output<Boolean>> isDefault() {
        return Optional.ofNullable(this.isDefault);
    }

    /**
     * (Updatable) The identifying key for the object.
     * 
     */
    @Import(name="key")
    private @Nullable Output<String> key;

    /**
     * @return (Updatable) The identifying key for the object.
     * 
     */
    public Optional<Output<String>> key() {
        return Optional.ofNullable(this.key);
    }

    /**
     * (Updatable) A summary type containing information about the object including its key, name, the time that it was created or updated, and the user who created or updated it.
     * 
     */
    @Import(name="metadata")
    private @Nullable Output<RegistryDataAssetDefaultConnectionMetadataArgs> metadata;

    /**
     * @return (Updatable) A summary type containing information about the object including its key, name, the time that it was created or updated, and the user who created or updated it.
     * 
     */
    public Optional<Output<RegistryDataAssetDefaultConnectionMetadataArgs>> metadata() {
        return Optional.ofNullable(this.metadata);
    }

    /**
     * (Updatable) The property which differentiates the subtypes.
     * 
     */
    @Import(name="modelType", required=true)
    private Output<String> modelType;

    /**
     * @return (Updatable) The property which differentiates the subtypes.
     * 
     */
    public Output<String> modelType() {
        return this.modelType;
    }

    /**
     * (Updatable) The model version of an object.
     * 
     */
    @Import(name="modelVersion")
    private @Nullable Output<String> modelVersion;

    /**
     * @return (Updatable) The model version of an object.
     * 
     */
    public Optional<Output<String>> modelVersion() {
        return Optional.ofNullable(this.modelVersion);
    }

    /**
     * (Updatable) Free form text without any restriction on the permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) Free form text without any restriction on the permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    @Import(name="objectStatus")
    private @Nullable Output<Integer> objectStatus;

    /**
     * @return (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    public Optional<Output<Integer>> objectStatus() {
        return Optional.ofNullable(this.objectStatus);
    }

    /**
     * (Updatable) The version of the object that is used to track changes in the object instance.
     * 
     */
    @Import(name="objectVersion")
    private @Nullable Output<Integer> objectVersion;

    /**
     * @return (Updatable) The version of the object that is used to track changes in the object instance.
     * 
     */
    public Optional<Output<Integer>> objectVersion() {
        return Optional.ofNullable(this.objectVersion);
    }

    /**
     * (Updatable) The schema object.
     * 
     */
    @Import(name="primarySchema")
    private @Nullable Output<RegistryDataAssetDefaultConnectionPrimarySchemaArgs> primarySchema;

    /**
     * @return (Updatable) The schema object.
     * 
     */
    public Optional<Output<RegistryDataAssetDefaultConnectionPrimarySchemaArgs>> primarySchema() {
        return Optional.ofNullable(this.primarySchema);
    }

    /**
     * (Updatable) All the properties for the data asset in a key-value map format.
     * 
     */
    @Import(name="properties", required=true)
    private Output<Map<String,Object>> properties;

    /**
     * @return (Updatable) All the properties for the data asset in a key-value map format.
     * 
     */
    public Output<Map<String,Object>> properties() {
        return this.properties;
    }

    /**
     * (Updatable) Information about the object and its parent.
     * 
     */
    @Import(name="registryMetadata")
    private @Nullable Output<RegistryDataAssetDefaultConnectionRegistryMetadataArgs> registryMetadata;

    /**
     * @return (Updatable) Information about the object and its parent.
     * 
     */
    public Optional<Output<RegistryDataAssetDefaultConnectionRegistryMetadataArgs>> registryMetadata() {
        return Optional.ofNullable(this.registryMetadata);
    }

    /**
     * (Updatable) Specific DataAsset Type
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return (Updatable) Specific DataAsset Type
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private RegistryDataAssetDefaultConnectionArgs() {}

    private RegistryDataAssetDefaultConnectionArgs(RegistryDataAssetDefaultConnectionArgs $) {
        this.connectionProperties = $.connectionProperties;
        this.description = $.description;
        this.identifier = $.identifier;
        this.isDefault = $.isDefault;
        this.key = $.key;
        this.metadata = $.metadata;
        this.modelType = $.modelType;
        this.modelVersion = $.modelVersion;
        this.name = $.name;
        this.objectStatus = $.objectStatus;
        this.objectVersion = $.objectVersion;
        this.primarySchema = $.primarySchema;
        this.properties = $.properties;
        this.registryMetadata = $.registryMetadata;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RegistryDataAssetDefaultConnectionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RegistryDataAssetDefaultConnectionArgs $;

        public Builder() {
            $ = new RegistryDataAssetDefaultConnectionArgs();
        }

        public Builder(RegistryDataAssetDefaultConnectionArgs defaults) {
            $ = new RegistryDataAssetDefaultConnectionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param connectionProperties (Updatable) The properties of the connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionProperties(@Nullable Output<List<RegistryDataAssetDefaultConnectionConnectionPropertyArgs>> connectionProperties) {
            $.connectionProperties = connectionProperties;
            return this;
        }

        /**
         * @param connectionProperties (Updatable) The properties of the connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionProperties(List<RegistryDataAssetDefaultConnectionConnectionPropertyArgs> connectionProperties) {
            return connectionProperties(Output.of(connectionProperties));
        }

        /**
         * @param connectionProperties (Updatable) The properties of the connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionProperties(RegistryDataAssetDefaultConnectionConnectionPropertyArgs... connectionProperties) {
            return connectionProperties(List.of(connectionProperties));
        }

        /**
         * @param description (Updatable) A user-defined description for the object.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-defined description for the object.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param identifier (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with an upper case letter or underscore. The value can be modified.
         * 
         * @return builder
         * 
         */
        public Builder identifier(Output<String> identifier) {
            $.identifier = identifier;
            return this;
        }

        /**
         * @param identifier (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with an upper case letter or underscore. The value can be modified.
         * 
         * @return builder
         * 
         */
        public Builder identifier(String identifier) {
            return identifier(Output.of(identifier));
        }

        /**
         * @param isDefault (Updatable) The default property of the connection.
         * 
         * @return builder
         * 
         */
        public Builder isDefault(@Nullable Output<Boolean> isDefault) {
            $.isDefault = isDefault;
            return this;
        }

        /**
         * @param isDefault (Updatable) The default property of the connection.
         * 
         * @return builder
         * 
         */
        public Builder isDefault(Boolean isDefault) {
            return isDefault(Output.of(isDefault));
        }

        /**
         * @param key (Updatable) The identifying key for the object.
         * 
         * @return builder
         * 
         */
        public Builder key(@Nullable Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key (Updatable) The identifying key for the object.
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        /**
         * @param metadata (Updatable) A summary type containing information about the object including its key, name, the time that it was created or updated, and the user who created or updated it.
         * 
         * @return builder
         * 
         */
        public Builder metadata(@Nullable Output<RegistryDataAssetDefaultConnectionMetadataArgs> metadata) {
            $.metadata = metadata;
            return this;
        }

        /**
         * @param metadata (Updatable) A summary type containing information about the object including its key, name, the time that it was created or updated, and the user who created or updated it.
         * 
         * @return builder
         * 
         */
        public Builder metadata(RegistryDataAssetDefaultConnectionMetadataArgs metadata) {
            return metadata(Output.of(metadata));
        }

        /**
         * @param modelType (Updatable) The property which differentiates the subtypes.
         * 
         * @return builder
         * 
         */
        public Builder modelType(Output<String> modelType) {
            $.modelType = modelType;
            return this;
        }

        /**
         * @param modelType (Updatable) The property which differentiates the subtypes.
         * 
         * @return builder
         * 
         */
        public Builder modelType(String modelType) {
            return modelType(Output.of(modelType));
        }

        /**
         * @param modelVersion (Updatable) The model version of an object.
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(@Nullable Output<String> modelVersion) {
            $.modelVersion = modelVersion;
            return this;
        }

        /**
         * @param modelVersion (Updatable) The model version of an object.
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(String modelVersion) {
            return modelVersion(Output.of(modelVersion));
        }

        /**
         * @param name (Updatable) Free form text without any restriction on the permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Free form text without any restriction on the permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param objectStatus (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
         * 
         * @return builder
         * 
         */
        public Builder objectStatus(@Nullable Output<Integer> objectStatus) {
            $.objectStatus = objectStatus;
            return this;
        }

        /**
         * @param objectStatus (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
         * 
         * @return builder
         * 
         */
        public Builder objectStatus(Integer objectStatus) {
            return objectStatus(Output.of(objectStatus));
        }

        /**
         * @param objectVersion (Updatable) The version of the object that is used to track changes in the object instance.
         * 
         * @return builder
         * 
         */
        public Builder objectVersion(@Nullable Output<Integer> objectVersion) {
            $.objectVersion = objectVersion;
            return this;
        }

        /**
         * @param objectVersion (Updatable) The version of the object that is used to track changes in the object instance.
         * 
         * @return builder
         * 
         */
        public Builder objectVersion(Integer objectVersion) {
            return objectVersion(Output.of(objectVersion));
        }

        /**
         * @param primarySchema (Updatable) The schema object.
         * 
         * @return builder
         * 
         */
        public Builder primarySchema(@Nullable Output<RegistryDataAssetDefaultConnectionPrimarySchemaArgs> primarySchema) {
            $.primarySchema = primarySchema;
            return this;
        }

        /**
         * @param primarySchema (Updatable) The schema object.
         * 
         * @return builder
         * 
         */
        public Builder primarySchema(RegistryDataAssetDefaultConnectionPrimarySchemaArgs primarySchema) {
            return primarySchema(Output.of(primarySchema));
        }

        /**
         * @param properties (Updatable) All the properties for the data asset in a key-value map format.
         * 
         * @return builder
         * 
         */
        public Builder properties(Output<Map<String,Object>> properties) {
            $.properties = properties;
            return this;
        }

        /**
         * @param properties (Updatable) All the properties for the data asset in a key-value map format.
         * 
         * @return builder
         * 
         */
        public Builder properties(Map<String,Object> properties) {
            return properties(Output.of(properties));
        }

        /**
         * @param registryMetadata (Updatable) Information about the object and its parent.
         * 
         * @return builder
         * 
         */
        public Builder registryMetadata(@Nullable Output<RegistryDataAssetDefaultConnectionRegistryMetadataArgs> registryMetadata) {
            $.registryMetadata = registryMetadata;
            return this;
        }

        /**
         * @param registryMetadata (Updatable) Information about the object and its parent.
         * 
         * @return builder
         * 
         */
        public Builder registryMetadata(RegistryDataAssetDefaultConnectionRegistryMetadataArgs registryMetadata) {
            return registryMetadata(Output.of(registryMetadata));
        }

        /**
         * @param type (Updatable) Specific DataAsset Type
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Specific DataAsset Type
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public RegistryDataAssetDefaultConnectionArgs build() {
            $.identifier = Objects.requireNonNull($.identifier, "expected parameter 'identifier' to be non-null");
            $.modelType = Objects.requireNonNull($.modelType, "expected parameter 'modelType' to be non-null");
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            $.properties = Objects.requireNonNull($.properties, "expected parameter 'properties' to be non-null");
            return $;
        }
    }

}