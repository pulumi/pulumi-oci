// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemLastRunDetail;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemParentRef;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemRegistryMetadata;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRef;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem {
    /**
     * @return The application key.
     * 
     */
    private String applicationKey;
    /**
     * @return The authorization mode for the task.
     * 
     */
    private String authMode;
    private String configProviderDelegate;
    /**
     * @return The description of the aggregator.
     * 
     */
    private String description;
    /**
     * @return The end time in milliseconds.
     * 
     */
    private String endTimeMillis;
    /**
     * @return The expected duration of the task execution.
     * 
     */
    private Double expectedDuration;
    /**
     * @return The expected duration unit of the task execution.
     * 
     */
    private String expectedDurationUnit;
    /**
     * @return Used to filter by the identifier of the object.
     * 
     */
    private String identifier;
    /**
     * @return Whether the backfill is enabled
     * 
     */
    private Boolean isBackfillEnabled;
    /**
     * @return Whether the same task can be executed concurrently.
     * 
     */
    private Boolean isConcurrentAllowed;
    /**
     * @return This filter parameter can be used to filter task schedule by its state.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return Used to filter by the key of the object.
     * 
     */
    private String key;
    /**
     * @return The last run details for the task run.
     * 
     */
    private List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemLastRunDetail> lastRunDetails;
    /**
     * @return A summary type containing information about the object including its key, name and when/who created/updated it.
     * 
     */
    private List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata> metadatas;
    /**
     * @return The type of the object.
     * 
     */
    private String modelType;
    /**
     * @return This is a version number that is used by the service to upgrade objects if needed through releases of the service.
     * 
     */
    private String modelVersion;
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    private String name;
    private String nextRunTimeMillis;
    private Integer numberOfRetries;
    /**
     * @return The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    private Integer objectStatus;
    /**
     * @return This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
     * 
     */
    private Integer objectVersion;
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemParentRef parentRef;
    private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemRegistryMetadata registryMetadata;
    /**
     * @return The number of retry attempts.
     * 
     */
    private Integer retryAttempts;
    /**
     * @return The retry delay, the unit for measurement is in the property retry delay unit.
     * 
     */
    private Double retryDelay;
    /**
     * @return The unit for the retry delay.
     * 
     */
    private String retryDelayUnit;
    /**
     * @return The schedule object
     * 
     */
    private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRef scheduleRef;
    /**
     * @return The start time in milliseconds.
     * 
     */
    private String startTimeMillis;
    /**
     * @return The workspace ID.
     * 
     */
    private String workspaceId;

    private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem() {}
    /**
     * @return The application key.
     * 
     */
    public String applicationKey() {
        return this.applicationKey;
    }
    /**
     * @return The authorization mode for the task.
     * 
     */
    public String authMode() {
        return this.authMode;
    }
    public String configProviderDelegate() {
        return this.configProviderDelegate;
    }
    /**
     * @return The description of the aggregator.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The end time in milliseconds.
     * 
     */
    public String endTimeMillis() {
        return this.endTimeMillis;
    }
    /**
     * @return The expected duration of the task execution.
     * 
     */
    public Double expectedDuration() {
        return this.expectedDuration;
    }
    /**
     * @return The expected duration unit of the task execution.
     * 
     */
    public String expectedDurationUnit() {
        return this.expectedDurationUnit;
    }
    /**
     * @return Used to filter by the identifier of the object.
     * 
     */
    public String identifier() {
        return this.identifier;
    }
    /**
     * @return Whether the backfill is enabled
     * 
     */
    public Boolean isBackfillEnabled() {
        return this.isBackfillEnabled;
    }
    /**
     * @return Whether the same task can be executed concurrently.
     * 
     */
    public Boolean isConcurrentAllowed() {
        return this.isConcurrentAllowed;
    }
    /**
     * @return This filter parameter can be used to filter task schedule by its state.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return Used to filter by the key of the object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The last run details for the task run.
     * 
     */
    public List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemLastRunDetail> lastRunDetails() {
        return this.lastRunDetails;
    }
    /**
     * @return A summary type containing information about the object including its key, name and when/who created/updated it.
     * 
     */
    public List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata> metadatas() {
        return this.metadatas;
    }
    /**
     * @return The type of the object.
     * 
     */
    public String modelType() {
        return this.modelType;
    }
    /**
     * @return This is a version number that is used by the service to upgrade objects if needed through releases of the service.
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
    public String nextRunTimeMillis() {
        return this.nextRunTimeMillis;
    }
    public Integer numberOfRetries() {
        return this.numberOfRetries;
    }
    /**
     * @return The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    public Integer objectStatus() {
        return this.objectStatus;
    }
    /**
     * @return This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
     * 
     */
    public Integer objectVersion() {
        return this.objectVersion;
    }
    /**
     * @return A reference to the object&#39;s parent.
     * 
     */
    public GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemParentRef parentRef() {
        return this.parentRef;
    }
    public GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemRegistryMetadata registryMetadata() {
        return this.registryMetadata;
    }
    /**
     * @return The number of retry attempts.
     * 
     */
    public Integer retryAttempts() {
        return this.retryAttempts;
    }
    /**
     * @return The retry delay, the unit for measurement is in the property retry delay unit.
     * 
     */
    public Double retryDelay() {
        return this.retryDelay;
    }
    /**
     * @return The unit for the retry delay.
     * 
     */
    public String retryDelayUnit() {
        return this.retryDelayUnit;
    }
    /**
     * @return The schedule object
     * 
     */
    public GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRef scheduleRef() {
        return this.scheduleRef;
    }
    /**
     * @return The start time in milliseconds.
     * 
     */
    public String startTimeMillis() {
        return this.startTimeMillis;
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

    public static Builder builder(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String applicationKey;
        private String authMode;
        private String configProviderDelegate;
        private String description;
        private String endTimeMillis;
        private Double expectedDuration;
        private String expectedDurationUnit;
        private String identifier;
        private Boolean isBackfillEnabled;
        private Boolean isConcurrentAllowed;
        private Boolean isEnabled;
        private String key;
        private List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemLastRunDetail> lastRunDetails;
        private List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata> metadatas;
        private String modelType;
        private String modelVersion;
        private String name;
        private String nextRunTimeMillis;
        private Integer numberOfRetries;
        private Integer objectStatus;
        private Integer objectVersion;
        private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemParentRef parentRef;
        private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemRegistryMetadata registryMetadata;
        private Integer retryAttempts;
        private Double retryDelay;
        private String retryDelayUnit;
        private GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRef scheduleRef;
        private String startTimeMillis;
        private String workspaceId;
        public Builder() {}
        public Builder(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationKey = defaults.applicationKey;
    	      this.authMode = defaults.authMode;
    	      this.configProviderDelegate = defaults.configProviderDelegate;
    	      this.description = defaults.description;
    	      this.endTimeMillis = defaults.endTimeMillis;
    	      this.expectedDuration = defaults.expectedDuration;
    	      this.expectedDurationUnit = defaults.expectedDurationUnit;
    	      this.identifier = defaults.identifier;
    	      this.isBackfillEnabled = defaults.isBackfillEnabled;
    	      this.isConcurrentAllowed = defaults.isConcurrentAllowed;
    	      this.isEnabled = defaults.isEnabled;
    	      this.key = defaults.key;
    	      this.lastRunDetails = defaults.lastRunDetails;
    	      this.metadatas = defaults.metadatas;
    	      this.modelType = defaults.modelType;
    	      this.modelVersion = defaults.modelVersion;
    	      this.name = defaults.name;
    	      this.nextRunTimeMillis = defaults.nextRunTimeMillis;
    	      this.numberOfRetries = defaults.numberOfRetries;
    	      this.objectStatus = defaults.objectStatus;
    	      this.objectVersion = defaults.objectVersion;
    	      this.parentRef = defaults.parentRef;
    	      this.registryMetadata = defaults.registryMetadata;
    	      this.retryAttempts = defaults.retryAttempts;
    	      this.retryDelay = defaults.retryDelay;
    	      this.retryDelayUnit = defaults.retryDelayUnit;
    	      this.scheduleRef = defaults.scheduleRef;
    	      this.startTimeMillis = defaults.startTimeMillis;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder applicationKey(String applicationKey) {
            if (applicationKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "applicationKey");
            }
            this.applicationKey = applicationKey;
            return this;
        }
        @CustomType.Setter
        public Builder authMode(String authMode) {
            if (authMode == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "authMode");
            }
            this.authMode = authMode;
            return this;
        }
        @CustomType.Setter
        public Builder configProviderDelegate(String configProviderDelegate) {
            if (configProviderDelegate == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "configProviderDelegate");
            }
            this.configProviderDelegate = configProviderDelegate;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder endTimeMillis(String endTimeMillis) {
            if (endTimeMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "endTimeMillis");
            }
            this.endTimeMillis = endTimeMillis;
            return this;
        }
        @CustomType.Setter
        public Builder expectedDuration(Double expectedDuration) {
            if (expectedDuration == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "expectedDuration");
            }
            this.expectedDuration = expectedDuration;
            return this;
        }
        @CustomType.Setter
        public Builder expectedDurationUnit(String expectedDurationUnit) {
            if (expectedDurationUnit == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "expectedDurationUnit");
            }
            this.expectedDurationUnit = expectedDurationUnit;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            if (identifier == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "identifier");
            }
            this.identifier = identifier;
            return this;
        }
        @CustomType.Setter
        public Builder isBackfillEnabled(Boolean isBackfillEnabled) {
            if (isBackfillEnabled == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "isBackfillEnabled");
            }
            this.isBackfillEnabled = isBackfillEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isConcurrentAllowed(Boolean isConcurrentAllowed) {
            if (isConcurrentAllowed == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "isConcurrentAllowed");
            }
            this.isConcurrentAllowed = isConcurrentAllowed;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder lastRunDetails(List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemLastRunDetail> lastRunDetails) {
            if (lastRunDetails == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "lastRunDetails");
            }
            this.lastRunDetails = lastRunDetails;
            return this;
        }
        public Builder lastRunDetails(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemLastRunDetail... lastRunDetails) {
            return lastRunDetails(List.of(lastRunDetails));
        }
        @CustomType.Setter
        public Builder metadatas(List<GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata> metadatas) {
            if (metadatas == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "metadatas");
            }
            this.metadatas = metadatas;
            return this;
        }
        public Builder metadatas(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemMetadata... metadatas) {
            return metadatas(List.of(metadatas));
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            if (modelType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "modelType");
            }
            this.modelType = modelType;
            return this;
        }
        @CustomType.Setter
        public Builder modelVersion(String modelVersion) {
            if (modelVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "modelVersion");
            }
            this.modelVersion = modelVersion;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder nextRunTimeMillis(String nextRunTimeMillis) {
            if (nextRunTimeMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "nextRunTimeMillis");
            }
            this.nextRunTimeMillis = nextRunTimeMillis;
            return this;
        }
        @CustomType.Setter
        public Builder numberOfRetries(Integer numberOfRetries) {
            if (numberOfRetries == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "numberOfRetries");
            }
            this.numberOfRetries = numberOfRetries;
            return this;
        }
        @CustomType.Setter
        public Builder objectStatus(Integer objectStatus) {
            if (objectStatus == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "objectStatus");
            }
            this.objectStatus = objectStatus;
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(Integer objectVersion) {
            if (objectVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "objectVersion");
            }
            this.objectVersion = objectVersion;
            return this;
        }
        @CustomType.Setter
        public Builder parentRef(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemParentRef parentRef) {
            if (parentRef == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "parentRef");
            }
            this.parentRef = parentRef;
            return this;
        }
        @CustomType.Setter
        public Builder registryMetadata(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemRegistryMetadata registryMetadata) {
            if (registryMetadata == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "registryMetadata");
            }
            this.registryMetadata = registryMetadata;
            return this;
        }
        @CustomType.Setter
        public Builder retryAttempts(Integer retryAttempts) {
            if (retryAttempts == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "retryAttempts");
            }
            this.retryAttempts = retryAttempts;
            return this;
        }
        @CustomType.Setter
        public Builder retryDelay(Double retryDelay) {
            if (retryDelay == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "retryDelay");
            }
            this.retryDelay = retryDelay;
            return this;
        }
        @CustomType.Setter
        public Builder retryDelayUnit(String retryDelayUnit) {
            if (retryDelayUnit == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "retryDelayUnit");
            }
            this.retryDelayUnit = retryDelayUnit;
            return this;
        }
        @CustomType.Setter
        public Builder scheduleRef(GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItemScheduleRef scheduleRef) {
            if (scheduleRef == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "scheduleRef");
            }
            this.scheduleRef = scheduleRef;
            return this;
        }
        @CustomType.Setter
        public Builder startTimeMillis(String startTimeMillis) {
            if (startTimeMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "startTimeMillis");
            }
            this.startTimeMillis = startTimeMillis;
            return this;
        }
        @CustomType.Setter
        public Builder workspaceId(String workspaceId) {
            if (workspaceId == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem", "workspaceId");
            }
            this.workspaceId = workspaceId;
            return this;
        }
        public GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem build() {
            final var _resultValue = new GetWorkspaceApplicationTaskSchedulesTaskScheduleSummaryCollectionItem();
            _resultValue.applicationKey = applicationKey;
            _resultValue.authMode = authMode;
            _resultValue.configProviderDelegate = configProviderDelegate;
            _resultValue.description = description;
            _resultValue.endTimeMillis = endTimeMillis;
            _resultValue.expectedDuration = expectedDuration;
            _resultValue.expectedDurationUnit = expectedDurationUnit;
            _resultValue.identifier = identifier;
            _resultValue.isBackfillEnabled = isBackfillEnabled;
            _resultValue.isConcurrentAllowed = isConcurrentAllowed;
            _resultValue.isEnabled = isEnabled;
            _resultValue.key = key;
            _resultValue.lastRunDetails = lastRunDetails;
            _resultValue.metadatas = metadatas;
            _resultValue.modelType = modelType;
            _resultValue.modelVersion = modelVersion;
            _resultValue.name = name;
            _resultValue.nextRunTimeMillis = nextRunTimeMillis;
            _resultValue.numberOfRetries = numberOfRetries;
            _resultValue.objectStatus = objectStatus;
            _resultValue.objectVersion = objectVersion;
            _resultValue.parentRef = parentRef;
            _resultValue.registryMetadata = registryMetadata;
            _resultValue.retryAttempts = retryAttempts;
            _resultValue.retryDelay = retryDelay;
            _resultValue.retryDelayUnit = retryDelayUnit;
            _resultValue.scheduleRef = scheduleRef;
            _resultValue.startTimeMillis = startTimeMillis;
            _resultValue.workspaceId = workspaceId;
            return _resultValue;
        }
    }
}
