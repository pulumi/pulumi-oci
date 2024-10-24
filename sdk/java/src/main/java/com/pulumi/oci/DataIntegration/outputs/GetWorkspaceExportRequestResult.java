// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceExportRequestExportedItem;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetWorkspaceExportRequestResult {
    /**
     * @return Controls if the references will be exported along with the objects
     * 
     */
    private Boolean areReferencesIncluded;
    /**
     * @return The name of the Object Storage Bucket where the objects will be exported to
     * 
     */
    private String bucket;
    /**
     * @return Name of the user who initiated export request.
     * 
     */
    private String createdBy;
    /**
     * @return Contains key of the error
     * 
     */
    private Map<String,String> errorMessages;
    private String exportRequestKey;
    /**
     * @return The array of exported object details.
     * 
     */
    private List<GetWorkspaceExportRequestExportedItem> exportedItems;
    /**
     * @return Name of the exported zip file.
     * 
     */
    private String fileName;
    /**
     * @return Export multiple objects based on filters.
     * 
     */
    private List<String> filters;
    private String id;
    /**
     * @return Flag to control whether to overwrite the object if it is already present at the provided object storage location.
     * 
     */
    private Boolean isObjectOverwriteEnabled;
    /**
     * @return Export object request key
     * 
     */
    private String key;
    /**
     * @return Name of the export request.
     * 
     */
    private String name;
    /**
     * @return The list of the objects to be exported
     * 
     */
    private List<String> objectKeys;
    /**
     * @return Region of the object storage (if using object storage of different region)
     * 
     */
    private String objectStorageRegion;
    /**
     * @return Optional parameter to point to object storage tenancy (if using Object Storage of different tenancy)
     * 
     */
    private String objectStorageTenancyId;
    /**
     * @return The array of exported referenced objects.
     * 
     */
    private String referencedItems;
    /**
     * @return Export Objects request status.
     * 
     */
    private String status;
    /**
     * @return Time at which the request was completely processed.
     * 
     */
    private String timeEndedInMillis;
    /**
     * @return Time at which the request started getting processed.
     * 
     */
    private String timeStartedInMillis;
    /**
     * @return Number of objects that are exported.
     * 
     */
    private Integer totalExportedObjectCount;
    private String workspaceId;

    private GetWorkspaceExportRequestResult() {}
    /**
     * @return Controls if the references will be exported along with the objects
     * 
     */
    public Boolean areReferencesIncluded() {
        return this.areReferencesIncluded;
    }
    /**
     * @return The name of the Object Storage Bucket where the objects will be exported to
     * 
     */
    public String bucket() {
        return this.bucket;
    }
    /**
     * @return Name of the user who initiated export request.
     * 
     */
    public String createdBy() {
        return this.createdBy;
    }
    /**
     * @return Contains key of the error
     * 
     */
    public Map<String,String> errorMessages() {
        return this.errorMessages;
    }
    public String exportRequestKey() {
        return this.exportRequestKey;
    }
    /**
     * @return The array of exported object details.
     * 
     */
    public List<GetWorkspaceExportRequestExportedItem> exportedItems() {
        return this.exportedItems;
    }
    /**
     * @return Name of the exported zip file.
     * 
     */
    public String fileName() {
        return this.fileName;
    }
    /**
     * @return Export multiple objects based on filters.
     * 
     */
    public List<String> filters() {
        return this.filters;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return Flag to control whether to overwrite the object if it is already present at the provided object storage location.
     * 
     */
    public Boolean isObjectOverwriteEnabled() {
        return this.isObjectOverwriteEnabled;
    }
    /**
     * @return Export object request key
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return Name of the export request.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The list of the objects to be exported
     * 
     */
    public List<String> objectKeys() {
        return this.objectKeys;
    }
    /**
     * @return Region of the object storage (if using object storage of different region)
     * 
     */
    public String objectStorageRegion() {
        return this.objectStorageRegion;
    }
    /**
     * @return Optional parameter to point to object storage tenancy (if using Object Storage of different tenancy)
     * 
     */
    public String objectStorageTenancyId() {
        return this.objectStorageTenancyId;
    }
    /**
     * @return The array of exported referenced objects.
     * 
     */
    public String referencedItems() {
        return this.referencedItems;
    }
    /**
     * @return Export Objects request status.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return Time at which the request was completely processed.
     * 
     */
    public String timeEndedInMillis() {
        return this.timeEndedInMillis;
    }
    /**
     * @return Time at which the request started getting processed.
     * 
     */
    public String timeStartedInMillis() {
        return this.timeStartedInMillis;
    }
    /**
     * @return Number of objects that are exported.
     * 
     */
    public Integer totalExportedObjectCount() {
        return this.totalExportedObjectCount;
    }
    public String workspaceId() {
        return this.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceExportRequestResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean areReferencesIncluded;
        private String bucket;
        private String createdBy;
        private Map<String,String> errorMessages;
        private String exportRequestKey;
        private List<GetWorkspaceExportRequestExportedItem> exportedItems;
        private String fileName;
        private List<String> filters;
        private String id;
        private Boolean isObjectOverwriteEnabled;
        private String key;
        private String name;
        private List<String> objectKeys;
        private String objectStorageRegion;
        private String objectStorageTenancyId;
        private String referencedItems;
        private String status;
        private String timeEndedInMillis;
        private String timeStartedInMillis;
        private Integer totalExportedObjectCount;
        private String workspaceId;
        public Builder() {}
        public Builder(GetWorkspaceExportRequestResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.areReferencesIncluded = defaults.areReferencesIncluded;
    	      this.bucket = defaults.bucket;
    	      this.createdBy = defaults.createdBy;
    	      this.errorMessages = defaults.errorMessages;
    	      this.exportRequestKey = defaults.exportRequestKey;
    	      this.exportedItems = defaults.exportedItems;
    	      this.fileName = defaults.fileName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.isObjectOverwriteEnabled = defaults.isObjectOverwriteEnabled;
    	      this.key = defaults.key;
    	      this.name = defaults.name;
    	      this.objectKeys = defaults.objectKeys;
    	      this.objectStorageRegion = defaults.objectStorageRegion;
    	      this.objectStorageTenancyId = defaults.objectStorageTenancyId;
    	      this.referencedItems = defaults.referencedItems;
    	      this.status = defaults.status;
    	      this.timeEndedInMillis = defaults.timeEndedInMillis;
    	      this.timeStartedInMillis = defaults.timeStartedInMillis;
    	      this.totalExportedObjectCount = defaults.totalExportedObjectCount;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder areReferencesIncluded(Boolean areReferencesIncluded) {
            if (areReferencesIncluded == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "areReferencesIncluded");
            }
            this.areReferencesIncluded = areReferencesIncluded;
            return this;
        }
        @CustomType.Setter
        public Builder bucket(String bucket) {
            if (bucket == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "bucket");
            }
            this.bucket = bucket;
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(String createdBy) {
            if (createdBy == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "createdBy");
            }
            this.createdBy = createdBy;
            return this;
        }
        @CustomType.Setter
        public Builder errorMessages(Map<String,String> errorMessages) {
            if (errorMessages == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "errorMessages");
            }
            this.errorMessages = errorMessages;
            return this;
        }
        @CustomType.Setter
        public Builder exportRequestKey(String exportRequestKey) {
            if (exportRequestKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "exportRequestKey");
            }
            this.exportRequestKey = exportRequestKey;
            return this;
        }
        @CustomType.Setter
        public Builder exportedItems(List<GetWorkspaceExportRequestExportedItem> exportedItems) {
            if (exportedItems == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "exportedItems");
            }
            this.exportedItems = exportedItems;
            return this;
        }
        public Builder exportedItems(GetWorkspaceExportRequestExportedItem... exportedItems) {
            return exportedItems(List.of(exportedItems));
        }
        @CustomType.Setter
        public Builder fileName(String fileName) {
            if (fileName == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "fileName");
            }
            this.fileName = fileName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(List<String> filters) {
            if (filters == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "filters");
            }
            this.filters = filters;
            return this;
        }
        public Builder filters(String... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isObjectOverwriteEnabled(Boolean isObjectOverwriteEnabled) {
            if (isObjectOverwriteEnabled == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "isObjectOverwriteEnabled");
            }
            this.isObjectOverwriteEnabled = isObjectOverwriteEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder objectKeys(List<String> objectKeys) {
            if (objectKeys == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "objectKeys");
            }
            this.objectKeys = objectKeys;
            return this;
        }
        public Builder objectKeys(String... objectKeys) {
            return objectKeys(List.of(objectKeys));
        }
        @CustomType.Setter
        public Builder objectStorageRegion(String objectStorageRegion) {
            if (objectStorageRegion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "objectStorageRegion");
            }
            this.objectStorageRegion = objectStorageRegion;
            return this;
        }
        @CustomType.Setter
        public Builder objectStorageTenancyId(String objectStorageTenancyId) {
            if (objectStorageTenancyId == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "objectStorageTenancyId");
            }
            this.objectStorageTenancyId = objectStorageTenancyId;
            return this;
        }
        @CustomType.Setter
        public Builder referencedItems(String referencedItems) {
            if (referencedItems == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "referencedItems");
            }
            this.referencedItems = referencedItems;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder timeEndedInMillis(String timeEndedInMillis) {
            if (timeEndedInMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "timeEndedInMillis");
            }
            this.timeEndedInMillis = timeEndedInMillis;
            return this;
        }
        @CustomType.Setter
        public Builder timeStartedInMillis(String timeStartedInMillis) {
            if (timeStartedInMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "timeStartedInMillis");
            }
            this.timeStartedInMillis = timeStartedInMillis;
            return this;
        }
        @CustomType.Setter
        public Builder totalExportedObjectCount(Integer totalExportedObjectCount) {
            if (totalExportedObjectCount == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "totalExportedObjectCount");
            }
            this.totalExportedObjectCount = totalExportedObjectCount;
            return this;
        }
        @CustomType.Setter
        public Builder workspaceId(String workspaceId) {
            if (workspaceId == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestResult", "workspaceId");
            }
            this.workspaceId = workspaceId;
            return this;
        }
        public GetWorkspaceExportRequestResult build() {
            final var _resultValue = new GetWorkspaceExportRequestResult();
            _resultValue.areReferencesIncluded = areReferencesIncluded;
            _resultValue.bucket = bucket;
            _resultValue.createdBy = createdBy;
            _resultValue.errorMessages = errorMessages;
            _resultValue.exportRequestKey = exportRequestKey;
            _resultValue.exportedItems = exportedItems;
            _resultValue.fileName = fileName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.isObjectOverwriteEnabled = isObjectOverwriteEnabled;
            _resultValue.key = key;
            _resultValue.name = name;
            _resultValue.objectKeys = objectKeys;
            _resultValue.objectStorageRegion = objectStorageRegion;
            _resultValue.objectStorageTenancyId = objectStorageTenancyId;
            _resultValue.referencedItems = referencedItems;
            _resultValue.status = status;
            _resultValue.timeEndedInMillis = timeEndedInMillis;
            _resultValue.timeStartedInMillis = timeStartedInMillis;
            _resultValue.totalExportedObjectCount = totalExportedObjectCount;
            _resultValue.workspaceId = workspaceId;
            return _resultValue;
        }
    }
}
