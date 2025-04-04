// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationPatchesPatchSummaryCollectionItemDependentObjectMetadata;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationPatchesPatchSummaryCollectionItemMetadata;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationPatchesPatchSummaryCollectionItemParentRef;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationPatchesPatchSummaryCollectionItemPatchObjectMetadata;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationPatchesPatchSummaryCollectionItemRegistryMetadata;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationPatchesPatchSummaryCollectionItem {
    /**
     * @return The application key.
     * 
     */
    private String applicationKey;
    /**
     * @return The application version of the patch.
     * 
     */
    private Integer applicationVersion;
    /**
     * @return List of dependent objects in this patch.
     * 
     */
    private List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemDependentObjectMetadata> dependentObjectMetadatas;
    /**
     * @return The description of the aggregator.
     * 
     */
    private String description;
    /**
     * @return The errors encountered while applying the patch, if any.
     * 
     */
    private Map<String,String> errorMessages;
    /**
     * @return Used to filter by the identifier of the published object.
     * 
     */
    private String identifier;
    /**
     * @return The key of the object.
     * 
     */
    private String key;
    /**
     * @return A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
     * 
     */
    private Map<String,String> keyMap;
    /**
     * @return A summary type containing information about the object including its key, name and when/who created/updated it.
     * 
     */
    private List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemMetadata> metadatas;
    /**
     * @return The object type.
     * 
     */
    private String modelType;
    /**
     * @return The object&#39;s model version.
     * 
     */
    private String modelVersion;
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    private String name;
    private List<String> objectKeys;
    /**
     * @return The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    private Integer objectStatus;
    /**
     * @return The object version.
     * 
     */
    private Integer objectVersion;
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    private List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemParentRef> parentReves;
    /**
     * @return List of objects that are published or unpublished in this patch.
     * 
     */
    private List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemPatchObjectMetadata> patchObjectMetadatas;
    /**
     * @return Status of the patch applied or being applied on the application
     * 
     */
    private String patchStatus;
    /**
     * @return The type of the patch applied or being applied on the application.
     * 
     */
    private String patchType;
    private GetWorkspaceApplicationPatchesPatchSummaryCollectionItemRegistryMetadata registryMetadata;
    /**
     * @return The date and time the patch was applied, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timePatched;
    /**
     * @return The workspace ID.
     * 
     */
    private String workspaceId;

    private GetWorkspaceApplicationPatchesPatchSummaryCollectionItem() {}
    /**
     * @return The application key.
     * 
     */
    public String applicationKey() {
        return this.applicationKey;
    }
    /**
     * @return The application version of the patch.
     * 
     */
    public Integer applicationVersion() {
        return this.applicationVersion;
    }
    /**
     * @return List of dependent objects in this patch.
     * 
     */
    public List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemDependentObjectMetadata> dependentObjectMetadatas() {
        return this.dependentObjectMetadatas;
    }
    /**
     * @return The description of the aggregator.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The errors encountered while applying the patch, if any.
     * 
     */
    public Map<String,String> errorMessages() {
        return this.errorMessages;
    }
    /**
     * @return Used to filter by the identifier of the published object.
     * 
     */
    public String identifier() {
        return this.identifier;
    }
    /**
     * @return The key of the object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return A key map. If provided, key is replaced with generated key. This structure provides mapping between user provided key and generated key.
     * 
     */
    public Map<String,String> keyMap() {
        return this.keyMap;
    }
    /**
     * @return A summary type containing information about the object including its key, name and when/who created/updated it.
     * 
     */
    public List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemMetadata> metadatas() {
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
     * @return The object&#39;s model version.
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
    public List<String> objectKeys() {
        return this.objectKeys;
    }
    /**
     * @return The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    public Integer objectStatus() {
        return this.objectStatus;
    }
    /**
     * @return The object version.
     * 
     */
    public Integer objectVersion() {
        return this.objectVersion;
    }
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    public List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemParentRef> parentReves() {
        return this.parentReves;
    }
    /**
     * @return List of objects that are published or unpublished in this patch.
     * 
     */
    public List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemPatchObjectMetadata> patchObjectMetadatas() {
        return this.patchObjectMetadatas;
    }
    /**
     * @return Status of the patch applied or being applied on the application
     * 
     */
    public String patchStatus() {
        return this.patchStatus;
    }
    /**
     * @return The type of the patch applied or being applied on the application.
     * 
     */
    public String patchType() {
        return this.patchType;
    }
    public GetWorkspaceApplicationPatchesPatchSummaryCollectionItemRegistryMetadata registryMetadata() {
        return this.registryMetadata;
    }
    /**
     * @return The date and time the patch was applied, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timePatched() {
        return this.timePatched;
    }
    /**
     * @return The workspace ID.
     * 
     */
    public String workspaceId() {
        return this.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationPatchesPatchSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String applicationKey;
        private Integer applicationVersion;
        private List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemDependentObjectMetadata> dependentObjectMetadatas;
        private String description;
        private Map<String,String> errorMessages;
        private String identifier;
        private String key;
        private Map<String,String> keyMap;
        private List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemMetadata> metadatas;
        private String modelType;
        private String modelVersion;
        private String name;
        private List<String> objectKeys;
        private Integer objectStatus;
        private Integer objectVersion;
        private List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemParentRef> parentReves;
        private List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemPatchObjectMetadata> patchObjectMetadatas;
        private String patchStatus;
        private String patchType;
        private GetWorkspaceApplicationPatchesPatchSummaryCollectionItemRegistryMetadata registryMetadata;
        private String timePatched;
        private String workspaceId;
        public Builder() {}
        public Builder(GetWorkspaceApplicationPatchesPatchSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationKey = defaults.applicationKey;
    	      this.applicationVersion = defaults.applicationVersion;
    	      this.dependentObjectMetadatas = defaults.dependentObjectMetadatas;
    	      this.description = defaults.description;
    	      this.errorMessages = defaults.errorMessages;
    	      this.identifier = defaults.identifier;
    	      this.key = defaults.key;
    	      this.keyMap = defaults.keyMap;
    	      this.metadatas = defaults.metadatas;
    	      this.modelType = defaults.modelType;
    	      this.modelVersion = defaults.modelVersion;
    	      this.name = defaults.name;
    	      this.objectKeys = defaults.objectKeys;
    	      this.objectStatus = defaults.objectStatus;
    	      this.objectVersion = defaults.objectVersion;
    	      this.parentReves = defaults.parentReves;
    	      this.patchObjectMetadatas = defaults.patchObjectMetadatas;
    	      this.patchStatus = defaults.patchStatus;
    	      this.patchType = defaults.patchType;
    	      this.registryMetadata = defaults.registryMetadata;
    	      this.timePatched = defaults.timePatched;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder applicationKey(String applicationKey) {
            if (applicationKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "applicationKey");
            }
            this.applicationKey = applicationKey;
            return this;
        }
        @CustomType.Setter
        public Builder applicationVersion(Integer applicationVersion) {
            if (applicationVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "applicationVersion");
            }
            this.applicationVersion = applicationVersion;
            return this;
        }
        @CustomType.Setter
        public Builder dependentObjectMetadatas(List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemDependentObjectMetadata> dependentObjectMetadatas) {
            if (dependentObjectMetadatas == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "dependentObjectMetadatas");
            }
            this.dependentObjectMetadatas = dependentObjectMetadatas;
            return this;
        }
        public Builder dependentObjectMetadatas(GetWorkspaceApplicationPatchesPatchSummaryCollectionItemDependentObjectMetadata... dependentObjectMetadatas) {
            return dependentObjectMetadatas(List.of(dependentObjectMetadatas));
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder errorMessages(Map<String,String> errorMessages) {
            if (errorMessages == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "errorMessages");
            }
            this.errorMessages = errorMessages;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            if (identifier == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "identifier");
            }
            this.identifier = identifier;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder keyMap(Map<String,String> keyMap) {
            if (keyMap == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "keyMap");
            }
            this.keyMap = keyMap;
            return this;
        }
        @CustomType.Setter
        public Builder metadatas(List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemMetadata> metadatas) {
            if (metadatas == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "metadatas");
            }
            this.metadatas = metadatas;
            return this;
        }
        public Builder metadatas(GetWorkspaceApplicationPatchesPatchSummaryCollectionItemMetadata... metadatas) {
            return metadatas(List.of(metadatas));
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            if (modelType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "modelType");
            }
            this.modelType = modelType;
            return this;
        }
        @CustomType.Setter
        public Builder modelVersion(String modelVersion) {
            if (modelVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "modelVersion");
            }
            this.modelVersion = modelVersion;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder objectKeys(List<String> objectKeys) {
            if (objectKeys == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "objectKeys");
            }
            this.objectKeys = objectKeys;
            return this;
        }
        public Builder objectKeys(String... objectKeys) {
            return objectKeys(List.of(objectKeys));
        }
        @CustomType.Setter
        public Builder objectStatus(Integer objectStatus) {
            if (objectStatus == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "objectStatus");
            }
            this.objectStatus = objectStatus;
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(Integer objectVersion) {
            if (objectVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "objectVersion");
            }
            this.objectVersion = objectVersion;
            return this;
        }
        @CustomType.Setter
        public Builder parentReves(List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemParentRef> parentReves) {
            if (parentReves == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "parentReves");
            }
            this.parentReves = parentReves;
            return this;
        }
        public Builder parentReves(GetWorkspaceApplicationPatchesPatchSummaryCollectionItemParentRef... parentReves) {
            return parentReves(List.of(parentReves));
        }
        @CustomType.Setter
        public Builder patchObjectMetadatas(List<GetWorkspaceApplicationPatchesPatchSummaryCollectionItemPatchObjectMetadata> patchObjectMetadatas) {
            if (patchObjectMetadatas == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "patchObjectMetadatas");
            }
            this.patchObjectMetadatas = patchObjectMetadatas;
            return this;
        }
        public Builder patchObjectMetadatas(GetWorkspaceApplicationPatchesPatchSummaryCollectionItemPatchObjectMetadata... patchObjectMetadatas) {
            return patchObjectMetadatas(List.of(patchObjectMetadatas));
        }
        @CustomType.Setter
        public Builder patchStatus(String patchStatus) {
            if (patchStatus == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "patchStatus");
            }
            this.patchStatus = patchStatus;
            return this;
        }
        @CustomType.Setter
        public Builder patchType(String patchType) {
            if (patchType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "patchType");
            }
            this.patchType = patchType;
            return this;
        }
        @CustomType.Setter
        public Builder registryMetadata(GetWorkspaceApplicationPatchesPatchSummaryCollectionItemRegistryMetadata registryMetadata) {
            if (registryMetadata == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "registryMetadata");
            }
            this.registryMetadata = registryMetadata;
            return this;
        }
        @CustomType.Setter
        public Builder timePatched(String timePatched) {
            if (timePatched == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "timePatched");
            }
            this.timePatched = timePatched;
            return this;
        }
        @CustomType.Setter
        public Builder workspaceId(String workspaceId) {
            if (workspaceId == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationPatchesPatchSummaryCollectionItem", "workspaceId");
            }
            this.workspaceId = workspaceId;
            return this;
        }
        public GetWorkspaceApplicationPatchesPatchSummaryCollectionItem build() {
            final var _resultValue = new GetWorkspaceApplicationPatchesPatchSummaryCollectionItem();
            _resultValue.applicationKey = applicationKey;
            _resultValue.applicationVersion = applicationVersion;
            _resultValue.dependentObjectMetadatas = dependentObjectMetadatas;
            _resultValue.description = description;
            _resultValue.errorMessages = errorMessages;
            _resultValue.identifier = identifier;
            _resultValue.key = key;
            _resultValue.keyMap = keyMap;
            _resultValue.metadatas = metadatas;
            _resultValue.modelType = modelType;
            _resultValue.modelVersion = modelVersion;
            _resultValue.name = name;
            _resultValue.objectKeys = objectKeys;
            _resultValue.objectStatus = objectStatus;
            _resultValue.objectVersion = objectVersion;
            _resultValue.parentReves = parentReves;
            _resultValue.patchObjectMetadatas = patchObjectMetadatas;
            _resultValue.patchStatus = patchStatus;
            _resultValue.patchType = patchType;
            _resultValue.registryMetadata = registryMetadata;
            _resultValue.timePatched = timePatched;
            _resultValue.workspaceId = workspaceId;
            return _resultValue;
        }
    }
}
