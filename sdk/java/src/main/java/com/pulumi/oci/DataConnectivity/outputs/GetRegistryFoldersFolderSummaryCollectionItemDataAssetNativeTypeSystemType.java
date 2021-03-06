// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataConnectivity.outputs.GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition;
import com.pulumi.oci.DataConnectivity.outputs.GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeParentRef;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemType {
    /**
     * @return The configuration details of a configurable object. This contains one or more config param definitions.
     * 
     */
    private final GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition configDefinition;
    /**
     * @return User-defined description for the folder.
     * 
     */
    private final String description;
    /**
     * @return The data type.
     * 
     */
    private final String dtType;
    /**
     * @return Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
     * 
     */
    private final String key;
    /**
     * @return The type of the folder.
     * 
     */
    private final String modelType;
    /**
     * @return The model version of an object.
     * 
     */
    private final String modelVersion;
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    private final String name;
    /**
     * @return The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    private final Integer objectStatus;
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    private final GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeParentRef parentRef;
    /**
     * @return The data type system name.
     * 
     */
    private final String typeSystemName;

    @CustomType.Constructor
    private GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemType(
        @CustomType.Parameter("configDefinition") GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition configDefinition,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("dtType") String dtType,
        @CustomType.Parameter("key") String key,
        @CustomType.Parameter("modelType") String modelType,
        @CustomType.Parameter("modelVersion") String modelVersion,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("objectStatus") Integer objectStatus,
        @CustomType.Parameter("parentRef") GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeParentRef parentRef,
        @CustomType.Parameter("typeSystemName") String typeSystemName) {
        this.configDefinition = configDefinition;
        this.description = description;
        this.dtType = dtType;
        this.key = key;
        this.modelType = modelType;
        this.modelVersion = modelVersion;
        this.name = name;
        this.objectStatus = objectStatus;
        this.parentRef = parentRef;
        this.typeSystemName = typeSystemName;
    }

    /**
     * @return The configuration details of a configurable object. This contains one or more config param definitions.
     * 
     */
    public GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition configDefinition() {
        return this.configDefinition;
    }
    /**
     * @return User-defined description for the folder.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The data type.
     * 
     */
    public String dtType() {
        return this.dtType;
    }
    /**
     * @return Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The type of the folder.
     * 
     */
    public String modelType() {
        return this.modelType;
    }
    /**
     * @return The model version of an object.
     * 
     */
    public String modelVersion() {
        return this.modelVersion;
    }
    /**
     * @return Used to filter by the name of the object.
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
     * @return A reference to the object&#39;s parent.
     * 
     */
    public GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeParentRef parentRef() {
        return this.parentRef;
    }
    /**
     * @return The data type system name.
     * 
     */
    public String typeSystemName() {
        return this.typeSystemName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemType defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition configDefinition;
        private String description;
        private String dtType;
        private String key;
        private String modelType;
        private String modelVersion;
        private String name;
        private Integer objectStatus;
        private GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeParentRef parentRef;
        private String typeSystemName;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemType defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configDefinition = defaults.configDefinition;
    	      this.description = defaults.description;
    	      this.dtType = defaults.dtType;
    	      this.key = defaults.key;
    	      this.modelType = defaults.modelType;
    	      this.modelVersion = defaults.modelVersion;
    	      this.name = defaults.name;
    	      this.objectStatus = defaults.objectStatus;
    	      this.parentRef = defaults.parentRef;
    	      this.typeSystemName = defaults.typeSystemName;
        }

        public Builder configDefinition(GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition configDefinition) {
            this.configDefinition = Objects.requireNonNull(configDefinition);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder dtType(String dtType) {
            this.dtType = Objects.requireNonNull(dtType);
            return this;
        }
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        public Builder modelType(String modelType) {
            this.modelType = Objects.requireNonNull(modelType);
            return this;
        }
        public Builder modelVersion(String modelVersion) {
            this.modelVersion = Objects.requireNonNull(modelVersion);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder objectStatus(Integer objectStatus) {
            this.objectStatus = Objects.requireNonNull(objectStatus);
            return this;
        }
        public Builder parentRef(GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeParentRef parentRef) {
            this.parentRef = Objects.requireNonNull(parentRef);
            return this;
        }
        public Builder typeSystemName(String typeSystemName) {
            this.typeSystemName = Objects.requireNonNull(typeSystemName);
            return this;
        }        public GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemType build() {
            return new GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemType(configDefinition, description, dtType, key, modelType, modelVersion, name, objectStatus, parentRef, typeSystemName);
        }
    }
}
