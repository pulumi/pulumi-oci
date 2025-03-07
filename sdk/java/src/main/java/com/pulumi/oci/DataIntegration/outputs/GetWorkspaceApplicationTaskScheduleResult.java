// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskScheduleLastRunDetail;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskScheduleMetadata;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskScheduleParentRef;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskScheduleRegistryMetadata;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceApplicationTaskScheduleScheduleRef;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationTaskScheduleResult {
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
    private String id;
    /**
     * @return The identifier of the aggregator.
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
     * @return Whether the schedule is enabled.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return The key of the aggregator object.
     * 
     */
    private String key;
    /**
     * @return The last run details for the task run.
     * 
     */
    private List<GetWorkspaceApplicationTaskScheduleLastRunDetail> lastRunDetails;
    /**
     * @return A summary type containing information about the object including its key, name and when/who created/updated it.
     * 
     */
    private List<GetWorkspaceApplicationTaskScheduleMetadata> metadatas;
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
     * @return Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
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
    private List<GetWorkspaceApplicationTaskScheduleParentRef> parentReves;
    private List<GetWorkspaceApplicationTaskScheduleRegistryMetadata> registryMetadatas;
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
    private List<GetWorkspaceApplicationTaskScheduleScheduleRef> scheduleReves;
    /**
     * @return The start time in milliseconds.
     * 
     */
    private String startTimeMillis;
    private String taskScheduleKey;
    private String workspaceId;

    private GetWorkspaceApplicationTaskScheduleResult() {}
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
     * @return Whether the schedule is enabled.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return The key of the aggregator object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The last run details for the task run.
     * 
     */
    public List<GetWorkspaceApplicationTaskScheduleLastRunDetail> lastRunDetails() {
        return this.lastRunDetails;
    }
    /**
     * @return A summary type containing information about the object including its key, name and when/who created/updated it.
     * 
     */
    public List<GetWorkspaceApplicationTaskScheduleMetadata> metadatas() {
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
     * @return Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
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
    public List<GetWorkspaceApplicationTaskScheduleParentRef> parentReves() {
        return this.parentReves;
    }
    public List<GetWorkspaceApplicationTaskScheduleRegistryMetadata> registryMetadatas() {
        return this.registryMetadatas;
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
    public List<GetWorkspaceApplicationTaskScheduleScheduleRef> scheduleReves() {
        return this.scheduleReves;
    }
    /**
     * @return The start time in milliseconds.
     * 
     */
    public String startTimeMillis() {
        return this.startTimeMillis;
    }
    public String taskScheduleKey() {
        return this.taskScheduleKey;
    }
    public String workspaceId() {
        return this.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationTaskScheduleResult defaults) {
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
        private String id;
        private String identifier;
        private Boolean isBackfillEnabled;
        private Boolean isConcurrentAllowed;
        private Boolean isEnabled;
        private String key;
        private List<GetWorkspaceApplicationTaskScheduleLastRunDetail> lastRunDetails;
        private List<GetWorkspaceApplicationTaskScheduleMetadata> metadatas;
        private String modelType;
        private String modelVersion;
        private String name;
        private String nextRunTimeMillis;
        private Integer numberOfRetries;
        private Integer objectStatus;
        private Integer objectVersion;
        private List<GetWorkspaceApplicationTaskScheduleParentRef> parentReves;
        private List<GetWorkspaceApplicationTaskScheduleRegistryMetadata> registryMetadatas;
        private Integer retryAttempts;
        private Double retryDelay;
        private String retryDelayUnit;
        private List<GetWorkspaceApplicationTaskScheduleScheduleRef> scheduleReves;
        private String startTimeMillis;
        private String taskScheduleKey;
        private String workspaceId;
        public Builder() {}
        public Builder(GetWorkspaceApplicationTaskScheduleResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationKey = defaults.applicationKey;
    	      this.authMode = defaults.authMode;
    	      this.configProviderDelegate = defaults.configProviderDelegate;
    	      this.description = defaults.description;
    	      this.endTimeMillis = defaults.endTimeMillis;
    	      this.expectedDuration = defaults.expectedDuration;
    	      this.expectedDurationUnit = defaults.expectedDurationUnit;
    	      this.id = defaults.id;
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
    	      this.parentReves = defaults.parentReves;
    	      this.registryMetadatas = defaults.registryMetadatas;
    	      this.retryAttempts = defaults.retryAttempts;
    	      this.retryDelay = defaults.retryDelay;
    	      this.retryDelayUnit = defaults.retryDelayUnit;
    	      this.scheduleReves = defaults.scheduleReves;
    	      this.startTimeMillis = defaults.startTimeMillis;
    	      this.taskScheduleKey = defaults.taskScheduleKey;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder applicationKey(String applicationKey) {
            if (applicationKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "applicationKey");
            }
            this.applicationKey = applicationKey;
            return this;
        }
        @CustomType.Setter
        public Builder authMode(String authMode) {
            if (authMode == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "authMode");
            }
            this.authMode = authMode;
            return this;
        }
        @CustomType.Setter
        public Builder configProviderDelegate(String configProviderDelegate) {
            if (configProviderDelegate == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "configProviderDelegate");
            }
            this.configProviderDelegate = configProviderDelegate;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder endTimeMillis(String endTimeMillis) {
            if (endTimeMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "endTimeMillis");
            }
            this.endTimeMillis = endTimeMillis;
            return this;
        }
        @CustomType.Setter
        public Builder expectedDuration(Double expectedDuration) {
            if (expectedDuration == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "expectedDuration");
            }
            this.expectedDuration = expectedDuration;
            return this;
        }
        @CustomType.Setter
        public Builder expectedDurationUnit(String expectedDurationUnit) {
            if (expectedDurationUnit == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "expectedDurationUnit");
            }
            this.expectedDurationUnit = expectedDurationUnit;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            if (identifier == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "identifier");
            }
            this.identifier = identifier;
            return this;
        }
        @CustomType.Setter
        public Builder isBackfillEnabled(Boolean isBackfillEnabled) {
            if (isBackfillEnabled == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "isBackfillEnabled");
            }
            this.isBackfillEnabled = isBackfillEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isConcurrentAllowed(Boolean isConcurrentAllowed) {
            if (isConcurrentAllowed == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "isConcurrentAllowed");
            }
            this.isConcurrentAllowed = isConcurrentAllowed;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder lastRunDetails(List<GetWorkspaceApplicationTaskScheduleLastRunDetail> lastRunDetails) {
            if (lastRunDetails == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "lastRunDetails");
            }
            this.lastRunDetails = lastRunDetails;
            return this;
        }
        public Builder lastRunDetails(GetWorkspaceApplicationTaskScheduleLastRunDetail... lastRunDetails) {
            return lastRunDetails(List.of(lastRunDetails));
        }
        @CustomType.Setter
        public Builder metadatas(List<GetWorkspaceApplicationTaskScheduleMetadata> metadatas) {
            if (metadatas == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "metadatas");
            }
            this.metadatas = metadatas;
            return this;
        }
        public Builder metadatas(GetWorkspaceApplicationTaskScheduleMetadata... metadatas) {
            return metadatas(List.of(metadatas));
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            if (modelType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "modelType");
            }
            this.modelType = modelType;
            return this;
        }
        @CustomType.Setter
        public Builder modelVersion(String modelVersion) {
            if (modelVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "modelVersion");
            }
            this.modelVersion = modelVersion;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder nextRunTimeMillis(String nextRunTimeMillis) {
            if (nextRunTimeMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "nextRunTimeMillis");
            }
            this.nextRunTimeMillis = nextRunTimeMillis;
            return this;
        }
        @CustomType.Setter
        public Builder numberOfRetries(Integer numberOfRetries) {
            if (numberOfRetries == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "numberOfRetries");
            }
            this.numberOfRetries = numberOfRetries;
            return this;
        }
        @CustomType.Setter
        public Builder objectStatus(Integer objectStatus) {
            if (objectStatus == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "objectStatus");
            }
            this.objectStatus = objectStatus;
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(Integer objectVersion) {
            if (objectVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "objectVersion");
            }
            this.objectVersion = objectVersion;
            return this;
        }
        @CustomType.Setter
        public Builder parentReves(List<GetWorkspaceApplicationTaskScheduleParentRef> parentReves) {
            if (parentReves == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "parentReves");
            }
            this.parentReves = parentReves;
            return this;
        }
        public Builder parentReves(GetWorkspaceApplicationTaskScheduleParentRef... parentReves) {
            return parentReves(List.of(parentReves));
        }
        @CustomType.Setter
        public Builder registryMetadatas(List<GetWorkspaceApplicationTaskScheduleRegistryMetadata> registryMetadatas) {
            if (registryMetadatas == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "registryMetadatas");
            }
            this.registryMetadatas = registryMetadatas;
            return this;
        }
        public Builder registryMetadatas(GetWorkspaceApplicationTaskScheduleRegistryMetadata... registryMetadatas) {
            return registryMetadatas(List.of(registryMetadatas));
        }
        @CustomType.Setter
        public Builder retryAttempts(Integer retryAttempts) {
            if (retryAttempts == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "retryAttempts");
            }
            this.retryAttempts = retryAttempts;
            return this;
        }
        @CustomType.Setter
        public Builder retryDelay(Double retryDelay) {
            if (retryDelay == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "retryDelay");
            }
            this.retryDelay = retryDelay;
            return this;
        }
        @CustomType.Setter
        public Builder retryDelayUnit(String retryDelayUnit) {
            if (retryDelayUnit == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "retryDelayUnit");
            }
            this.retryDelayUnit = retryDelayUnit;
            return this;
        }
        @CustomType.Setter
        public Builder scheduleReves(List<GetWorkspaceApplicationTaskScheduleScheduleRef> scheduleReves) {
            if (scheduleReves == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "scheduleReves");
            }
            this.scheduleReves = scheduleReves;
            return this;
        }
        public Builder scheduleReves(GetWorkspaceApplicationTaskScheduleScheduleRef... scheduleReves) {
            return scheduleReves(List.of(scheduleReves));
        }
        @CustomType.Setter
        public Builder startTimeMillis(String startTimeMillis) {
            if (startTimeMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "startTimeMillis");
            }
            this.startTimeMillis = startTimeMillis;
            return this;
        }
        @CustomType.Setter
        public Builder taskScheduleKey(String taskScheduleKey) {
            if (taskScheduleKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "taskScheduleKey");
            }
            this.taskScheduleKey = taskScheduleKey;
            return this;
        }
        @CustomType.Setter
        public Builder workspaceId(String workspaceId) {
            if (workspaceId == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationTaskScheduleResult", "workspaceId");
            }
            this.workspaceId = workspaceId;
            return this;
        }
        public GetWorkspaceApplicationTaskScheduleResult build() {
            final var _resultValue = new GetWorkspaceApplicationTaskScheduleResult();
            _resultValue.applicationKey = applicationKey;
            _resultValue.authMode = authMode;
            _resultValue.configProviderDelegate = configProviderDelegate;
            _resultValue.description = description;
            _resultValue.endTimeMillis = endTimeMillis;
            _resultValue.expectedDuration = expectedDuration;
            _resultValue.expectedDurationUnit = expectedDurationUnit;
            _resultValue.id = id;
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
            _resultValue.parentReves = parentReves;
            _resultValue.registryMetadatas = registryMetadatas;
            _resultValue.retryAttempts = retryAttempts;
            _resultValue.retryDelay = retryDelay;
            _resultValue.retryDelayUnit = retryDelayUnit;
            _resultValue.scheduleReves = scheduleReves;
            _resultValue.startTimeMillis = startTimeMillis;
            _resultValue.taskScheduleKey = taskScheduleKey;
            _resultValue.workspaceId = workspaceId;
            return _resultValue;
        }
    }
}
