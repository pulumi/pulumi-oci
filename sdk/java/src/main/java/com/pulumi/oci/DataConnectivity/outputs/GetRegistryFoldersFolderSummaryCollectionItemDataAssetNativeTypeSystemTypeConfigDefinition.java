// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataConnectivity.outputs.GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinitionParentRef;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition {
    /**
     * @return The parameter configuration details.
     * 
     */
    private Map<String,Object> configParameterDefinitions;
    /**
     * @return Specifies whether the configuration is contained.
     * 
     */
    private Boolean isContained;
    /**
     * @return Generated key that can be used in API calls to identify the folder. In scenarios where reference to the folder is required, a value can be passed in create.
     * 
     */
    private String key;
    /**
     * @return The type of the folder.
     * 
     */
    private String modelType;
    /**
     * @return The model version of an object.
     * 
     */
    private String modelVersion;
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    private String name;
    /**
     * @return The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    private Integer objectStatus;
    /**
     * @return A reference to the parent object.
     * 
     */
    private GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinitionParentRef parentRef;

    private GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition() {}
    /**
     * @return The parameter configuration details.
     * 
     */
    public Map<String,Object> configParameterDefinitions() {
        return this.configParameterDefinitions;
    }
    /**
     * @return Specifies whether the configuration is contained.
     * 
     */
    public Boolean isContained() {
        return this.isContained;
    }
    /**
     * @return Generated key that can be used in API calls to identify the folder. In scenarios where reference to the folder is required, a value can be passed in create.
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
     * @return A reference to the parent object.
     * 
     */
    public GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinitionParentRef parentRef() {
        return this.parentRef;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Map<String,Object> configParameterDefinitions;
        private Boolean isContained;
        private String key;
        private String modelType;
        private String modelVersion;
        private String name;
        private Integer objectStatus;
        private GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinitionParentRef parentRef;
        public Builder() {}
        public Builder(GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configParameterDefinitions = defaults.configParameterDefinitions;
    	      this.isContained = defaults.isContained;
    	      this.key = defaults.key;
    	      this.modelType = defaults.modelType;
    	      this.modelVersion = defaults.modelVersion;
    	      this.name = defaults.name;
    	      this.objectStatus = defaults.objectStatus;
    	      this.parentRef = defaults.parentRef;
        }

        @CustomType.Setter
        public Builder configParameterDefinitions(Map<String,Object> configParameterDefinitions) {
            this.configParameterDefinitions = Objects.requireNonNull(configParameterDefinitions);
            return this;
        }
        @CustomType.Setter
        public Builder isContained(Boolean isContained) {
            this.isContained = Objects.requireNonNull(isContained);
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
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
        public Builder parentRef(GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinitionParentRef parentRef) {
            this.parentRef = Objects.requireNonNull(parentRef);
            return this;
        }
        public GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition build() {
            final var o = new GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeConfigDefinition();
            o.configParameterDefinitions = configParameterDefinitions;
            o.isContained = isContained;
            o.key = key;
            o.modelType = modelType;
            o.modelVersion = modelVersion;
            o.name = name;
            o.objectStatus = objectStatus;
            o.parentRef = parentRef;
            return o;
        }
    }
}