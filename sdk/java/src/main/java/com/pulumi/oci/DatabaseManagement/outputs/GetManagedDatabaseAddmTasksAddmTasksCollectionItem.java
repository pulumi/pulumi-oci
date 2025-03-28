// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseAddmTasksAddmTasksCollectionItem {
    /**
     * @return The ID number of the beginning AWR snapshot.
     * 
     */
    private String beginSnapshotId;
    /**
     * @return The database user who owns the ADDM task.
     * 
     */
    private String dbUser;
    /**
     * @return The description of the ADDM task.
     * 
     */
    private String description;
    /**
     * @return The ID number of the ending AWR snapshot.
     * 
     */
    private String endSnapshotId;
    /**
     * @return The timestamp of the ending AWR snapshot used in the ADDM task as defined by date-time RFC3339 format.
     * 
     */
    private String endSnapshotTime;
    /**
     * @return The number of ADDM findings.
     * 
     */
    private String findings;
    /**
     * @return A description of how the task was created.
     * 
     */
    private String howCreated;
    /**
     * @return The timestamp of the beginning AWR snapshot used in the ADDM task as defined by date-time RFC3339 format.
     * 
     */
    private String startSnapshotTime;
    /**
     * @return The status of the ADDM task.
     * 
     */
    private String status;
    /**
     * @return The ID number of the ADDM task.
     * 
     */
    private String taskId;
    /**
     * @return The name of the ADDM task.
     * 
     */
    private String taskName;
    /**
     * @return The creation date of the ADDM task.
     * 
     */
    private String timeCreated;

    private GetManagedDatabaseAddmTasksAddmTasksCollectionItem() {}
    /**
     * @return The ID number of the beginning AWR snapshot.
     * 
     */
    public String beginSnapshotId() {
        return this.beginSnapshotId;
    }
    /**
     * @return The database user who owns the ADDM task.
     * 
     */
    public String dbUser() {
        return this.dbUser;
    }
    /**
     * @return The description of the ADDM task.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The ID number of the ending AWR snapshot.
     * 
     */
    public String endSnapshotId() {
        return this.endSnapshotId;
    }
    /**
     * @return The timestamp of the ending AWR snapshot used in the ADDM task as defined by date-time RFC3339 format.
     * 
     */
    public String endSnapshotTime() {
        return this.endSnapshotTime;
    }
    /**
     * @return The number of ADDM findings.
     * 
     */
    public String findings() {
        return this.findings;
    }
    /**
     * @return A description of how the task was created.
     * 
     */
    public String howCreated() {
        return this.howCreated;
    }
    /**
     * @return The timestamp of the beginning AWR snapshot used in the ADDM task as defined by date-time RFC3339 format.
     * 
     */
    public String startSnapshotTime() {
        return this.startSnapshotTime;
    }
    /**
     * @return The status of the ADDM task.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The ID number of the ADDM task.
     * 
     */
    public String taskId() {
        return this.taskId;
    }
    /**
     * @return The name of the ADDM task.
     * 
     */
    public String taskName() {
        return this.taskName;
    }
    /**
     * @return The creation date of the ADDM task.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseAddmTasksAddmTasksCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String beginSnapshotId;
        private String dbUser;
        private String description;
        private String endSnapshotId;
        private String endSnapshotTime;
        private String findings;
        private String howCreated;
        private String startSnapshotTime;
        private String status;
        private String taskId;
        private String taskName;
        private String timeCreated;
        public Builder() {}
        public Builder(GetManagedDatabaseAddmTasksAddmTasksCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.beginSnapshotId = defaults.beginSnapshotId;
    	      this.dbUser = defaults.dbUser;
    	      this.description = defaults.description;
    	      this.endSnapshotId = defaults.endSnapshotId;
    	      this.endSnapshotTime = defaults.endSnapshotTime;
    	      this.findings = defaults.findings;
    	      this.howCreated = defaults.howCreated;
    	      this.startSnapshotTime = defaults.startSnapshotTime;
    	      this.status = defaults.status;
    	      this.taskId = defaults.taskId;
    	      this.taskName = defaults.taskName;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder beginSnapshotId(String beginSnapshotId) {
            if (beginSnapshotId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "beginSnapshotId");
            }
            this.beginSnapshotId = beginSnapshotId;
            return this;
        }
        @CustomType.Setter
        public Builder dbUser(String dbUser) {
            if (dbUser == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "dbUser");
            }
            this.dbUser = dbUser;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder endSnapshotId(String endSnapshotId) {
            if (endSnapshotId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "endSnapshotId");
            }
            this.endSnapshotId = endSnapshotId;
            return this;
        }
        @CustomType.Setter
        public Builder endSnapshotTime(String endSnapshotTime) {
            if (endSnapshotTime == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "endSnapshotTime");
            }
            this.endSnapshotTime = endSnapshotTime;
            return this;
        }
        @CustomType.Setter
        public Builder findings(String findings) {
            if (findings == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "findings");
            }
            this.findings = findings;
            return this;
        }
        @CustomType.Setter
        public Builder howCreated(String howCreated) {
            if (howCreated == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "howCreated");
            }
            this.howCreated = howCreated;
            return this;
        }
        @CustomType.Setter
        public Builder startSnapshotTime(String startSnapshotTime) {
            if (startSnapshotTime == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "startSnapshotTime");
            }
            this.startSnapshotTime = startSnapshotTime;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder taskId(String taskId) {
            if (taskId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "taskId");
            }
            this.taskId = taskId;
            return this;
        }
        @CustomType.Setter
        public Builder taskName(String taskName) {
            if (taskName == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "taskName");
            }
            this.taskName = taskName;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseAddmTasksAddmTasksCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetManagedDatabaseAddmTasksAddmTasksCollectionItem build() {
            final var _resultValue = new GetManagedDatabaseAddmTasksAddmTasksCollectionItem();
            _resultValue.beginSnapshotId = beginSnapshotId;
            _resultValue.dbUser = dbUser;
            _resultValue.description = description;
            _resultValue.endSnapshotId = endSnapshotId;
            _resultValue.endSnapshotTime = endSnapshotTime;
            _resultValue.findings = findings;
            _resultValue.howCreated = howCreated;
            _resultValue.startSnapshotTime = startSnapshotTime;
            _resultValue.status = status;
            _resultValue.taskId = taskId;
            _resultValue.taskName = taskName;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
