// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetail;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailProperty;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail {
    /**
     * @return A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    private String description;
    /**
     * @return Execution details.
     * 
     */
    private List<GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetail> executionDetails;
    /**
     * @return Is this an Apply Subject Task? Ex. Patch Execution Task
     * 
     */
    private Boolean isApplySubjectTask;
    /**
     * @return Make a copy of this task in Library
     * 
     */
    private Boolean isCopyToLibraryEnabled;
    /**
     * @return Is this a discovery output task?
     * 
     */
    private Boolean isDiscoveryOutputTask;
    /**
     * @return The name of the task
     * 
     */
    private String name;
    /**
     * @return The OS type for the runbook.
     * 
     */
    private String osType;
    /**
     * @return A filter to return runbooks whose platform matches the given platform.
     * 
     */
    private String platform;
    /**
     * @return The properties of the task.
     * 
     */
    private List<GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailProperty> properties;
    /**
     * @return The scope of the task.
     * 
     */
    private String scope;
    /**
     * @return The ID of taskRecord.
     * 
     */
    private String taskRecordId;

    private GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail() {}
    /**
     * @return A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Execution details.
     * 
     */
    public List<GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetail> executionDetails() {
        return this.executionDetails;
    }
    /**
     * @return Is this an Apply Subject Task? Ex. Patch Execution Task
     * 
     */
    public Boolean isApplySubjectTask() {
        return this.isApplySubjectTask;
    }
    /**
     * @return Make a copy of this task in Library
     * 
     */
    public Boolean isCopyToLibraryEnabled() {
        return this.isCopyToLibraryEnabled;
    }
    /**
     * @return Is this a discovery output task?
     * 
     */
    public Boolean isDiscoveryOutputTask() {
        return this.isDiscoveryOutputTask;
    }
    /**
     * @return The name of the task
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The OS type for the runbook.
     * 
     */
    public String osType() {
        return this.osType;
    }
    /**
     * @return A filter to return runbooks whose platform matches the given platform.
     * 
     */
    public String platform() {
        return this.platform;
    }
    /**
     * @return The properties of the task.
     * 
     */
    public List<GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailProperty> properties() {
        return this.properties;
    }
    /**
     * @return The scope of the task.
     * 
     */
    public String scope() {
        return this.scope;
    }
    /**
     * @return The ID of taskRecord.
     * 
     */
    public String taskRecordId() {
        return this.taskRecordId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private List<GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetail> executionDetails;
        private Boolean isApplySubjectTask;
        private Boolean isCopyToLibraryEnabled;
        private Boolean isDiscoveryOutputTask;
        private String name;
        private String osType;
        private String platform;
        private List<GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailProperty> properties;
        private String scope;
        private String taskRecordId;
        public Builder() {}
        public Builder(GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.executionDetails = defaults.executionDetails;
    	      this.isApplySubjectTask = defaults.isApplySubjectTask;
    	      this.isCopyToLibraryEnabled = defaults.isCopyToLibraryEnabled;
    	      this.isDiscoveryOutputTask = defaults.isDiscoveryOutputTask;
    	      this.name = defaults.name;
    	      this.osType = defaults.osType;
    	      this.platform = defaults.platform;
    	      this.properties = defaults.properties;
    	      this.scope = defaults.scope;
    	      this.taskRecordId = defaults.taskRecordId;
        }

        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder executionDetails(List<GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetail> executionDetails) {
            if (executionDetails == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "executionDetails");
            }
            this.executionDetails = executionDetails;
            return this;
        }
        public Builder executionDetails(GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailExecutionDetail... executionDetails) {
            return executionDetails(List.of(executionDetails));
        }
        @CustomType.Setter
        public Builder isApplySubjectTask(Boolean isApplySubjectTask) {
            if (isApplySubjectTask == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "isApplySubjectTask");
            }
            this.isApplySubjectTask = isApplySubjectTask;
            return this;
        }
        @CustomType.Setter
        public Builder isCopyToLibraryEnabled(Boolean isCopyToLibraryEnabled) {
            if (isCopyToLibraryEnabled == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "isCopyToLibraryEnabled");
            }
            this.isCopyToLibraryEnabled = isCopyToLibraryEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isDiscoveryOutputTask(Boolean isDiscoveryOutputTask) {
            if (isDiscoveryOutputTask == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "isDiscoveryOutputTask");
            }
            this.isDiscoveryOutputTask = isDiscoveryOutputTask;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder osType(String osType) {
            if (osType == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "osType");
            }
            this.osType = osType;
            return this;
        }
        @CustomType.Setter
        public Builder platform(String platform) {
            if (platform == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "platform");
            }
            this.platform = platform;
            return this;
        }
        @CustomType.Setter
        public Builder properties(List<GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailProperty> properties) {
            if (properties == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "properties");
            }
            this.properties = properties;
            return this;
        }
        public Builder properties(GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetailProperty... properties) {
            return properties(List.of(properties));
        }
        @CustomType.Setter
        public Builder scope(String scope) {
            if (scope == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "scope");
            }
            this.scope = scope;
            return this;
        }
        @CustomType.Setter
        public Builder taskRecordId(String taskRecordId) {
            if (taskRecordId == null) {
              throw new MissingRequiredPropertyException("GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail", "taskRecordId");
            }
            this.taskRecordId = taskRecordId;
            return this;
        }
        public GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail build() {
            final var _resultValue = new GetRunbooksRunbookCollectionItemAssociationTaskTaskRecordDetail();
            _resultValue.description = description;
            _resultValue.executionDetails = executionDetails;
            _resultValue.isApplySubjectTask = isApplySubjectTask;
            _resultValue.isCopyToLibraryEnabled = isCopyToLibraryEnabled;
            _resultValue.isDiscoveryOutputTask = isDiscoveryOutputTask;
            _resultValue.name = name;
            _resultValue.osType = osType;
            _resultValue.platform = platform;
            _resultValue.properties = properties;
            _resultValue.scope = scope;
            _resultValue.taskRecordId = taskRecordId;
            return _resultValue;
        }
    }
}
