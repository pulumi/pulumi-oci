// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabase;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseOptimizerStatisticsCollectionOperationTask;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseOptimizerStatisticsCollectionOperationResult {
    /**
     * @return The number of objects for which statistics collection is completed.
     * 
     */
    private Integer completedCount;
    /**
     * @return The summary of the Managed Database resource.
     * 
     */
    private List<GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabase> databases;
    /**
     * @return The time it takes to complete the operation (in seconds).
     * 
     */
    private Double durationInSeconds;
    /**
     * @return The end time of the operation.
     * 
     */
    private String endTime;
    /**
     * @return The number of objects for which statistics collection failed.
     * 
     */
    private Integer failedCount;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The number of objects for which statistics collection is in progress.
     * 
     */
    private Integer inProgressCount;
    /**
     * @return The name of the job.
     * 
     */
    private String jobName;
    private String managedDatabaseId;
    /**
     * @return The name of the operation.
     * 
     */
    private String operationName;
    private Double optimizerStatisticsCollectionOperationId;
    /**
     * @return The start time of the operation.
     * 
     */
    private String startTime;
    /**
     * @return The status of the Optimizer Statistics Collection task.
     * 
     */
    private String status;
    /**
     * @return The name of the target object for which statistics are gathered.
     * 
     */
    private String target;
    /**
     * @return An array of Optimizer Statistics Collection task details.
     * 
     */
    private List<GetManagedDatabaseOptimizerStatisticsCollectionOperationTask> tasks;
    /**
     * @return The number of objects for which statistics collection timed out.
     * 
     */
    private Integer timedOutCount;
    /**
     * @return The total number of objects for which statistics is collected. This number is the sum of all the objects with various statuses: completed, inProgress, failed, and timedOut.
     * 
     */
    private Integer totalObjectsCount;

    private GetManagedDatabaseOptimizerStatisticsCollectionOperationResult() {}
    /**
     * @return The number of objects for which statistics collection is completed.
     * 
     */
    public Integer completedCount() {
        return this.completedCount;
    }
    /**
     * @return The summary of the Managed Database resource.
     * 
     */
    public List<GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabase> databases() {
        return this.databases;
    }
    /**
     * @return The time it takes to complete the operation (in seconds).
     * 
     */
    public Double durationInSeconds() {
        return this.durationInSeconds;
    }
    /**
     * @return The end time of the operation.
     * 
     */
    public String endTime() {
        return this.endTime;
    }
    /**
     * @return The number of objects for which statistics collection failed.
     * 
     */
    public Integer failedCount() {
        return this.failedCount;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The number of objects for which statistics collection is in progress.
     * 
     */
    public Integer inProgressCount() {
        return this.inProgressCount;
    }
    /**
     * @return The name of the job.
     * 
     */
    public String jobName() {
        return this.jobName;
    }
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }
    /**
     * @return The name of the operation.
     * 
     */
    public String operationName() {
        return this.operationName;
    }
    public Double optimizerStatisticsCollectionOperationId() {
        return this.optimizerStatisticsCollectionOperationId;
    }
    /**
     * @return The start time of the operation.
     * 
     */
    public String startTime() {
        return this.startTime;
    }
    /**
     * @return The status of the Optimizer Statistics Collection task.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The name of the target object for which statistics are gathered.
     * 
     */
    public String target() {
        return this.target;
    }
    /**
     * @return An array of Optimizer Statistics Collection task details.
     * 
     */
    public List<GetManagedDatabaseOptimizerStatisticsCollectionOperationTask> tasks() {
        return this.tasks;
    }
    /**
     * @return The number of objects for which statistics collection timed out.
     * 
     */
    public Integer timedOutCount() {
        return this.timedOutCount;
    }
    /**
     * @return The total number of objects for which statistics is collected. This number is the sum of all the objects with various statuses: completed, inProgress, failed, and timedOut.
     * 
     */
    public Integer totalObjectsCount() {
        return this.totalObjectsCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseOptimizerStatisticsCollectionOperationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer completedCount;
        private List<GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabase> databases;
        private Double durationInSeconds;
        private String endTime;
        private Integer failedCount;
        private String id;
        private Integer inProgressCount;
        private String jobName;
        private String managedDatabaseId;
        private String operationName;
        private Double optimizerStatisticsCollectionOperationId;
        private String startTime;
        private String status;
        private String target;
        private List<GetManagedDatabaseOptimizerStatisticsCollectionOperationTask> tasks;
        private Integer timedOutCount;
        private Integer totalObjectsCount;
        public Builder() {}
        public Builder(GetManagedDatabaseOptimizerStatisticsCollectionOperationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.completedCount = defaults.completedCount;
    	      this.databases = defaults.databases;
    	      this.durationInSeconds = defaults.durationInSeconds;
    	      this.endTime = defaults.endTime;
    	      this.failedCount = defaults.failedCount;
    	      this.id = defaults.id;
    	      this.inProgressCount = defaults.inProgressCount;
    	      this.jobName = defaults.jobName;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.operationName = defaults.operationName;
    	      this.optimizerStatisticsCollectionOperationId = defaults.optimizerStatisticsCollectionOperationId;
    	      this.startTime = defaults.startTime;
    	      this.status = defaults.status;
    	      this.target = defaults.target;
    	      this.tasks = defaults.tasks;
    	      this.timedOutCount = defaults.timedOutCount;
    	      this.totalObjectsCount = defaults.totalObjectsCount;
        }

        @CustomType.Setter
        public Builder completedCount(Integer completedCount) {
            this.completedCount = Objects.requireNonNull(completedCount);
            return this;
        }
        @CustomType.Setter
        public Builder databases(List<GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabase> databases) {
            this.databases = Objects.requireNonNull(databases);
            return this;
        }
        public Builder databases(GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabase... databases) {
            return databases(List.of(databases));
        }
        @CustomType.Setter
        public Builder durationInSeconds(Double durationInSeconds) {
            this.durationInSeconds = Objects.requireNonNull(durationInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder endTime(String endTime) {
            this.endTime = Objects.requireNonNull(endTime);
            return this;
        }
        @CustomType.Setter
        public Builder failedCount(Integer failedCount) {
            this.failedCount = Objects.requireNonNull(failedCount);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder inProgressCount(Integer inProgressCount) {
            this.inProgressCount = Objects.requireNonNull(inProgressCount);
            return this;
        }
        @CustomType.Setter
        public Builder jobName(String jobName) {
            this.jobName = Objects.requireNonNull(jobName);
            return this;
        }
        @CustomType.Setter
        public Builder managedDatabaseId(String managedDatabaseId) {
            this.managedDatabaseId = Objects.requireNonNull(managedDatabaseId);
            return this;
        }
        @CustomType.Setter
        public Builder operationName(String operationName) {
            this.operationName = Objects.requireNonNull(operationName);
            return this;
        }
        @CustomType.Setter
        public Builder optimizerStatisticsCollectionOperationId(Double optimizerStatisticsCollectionOperationId) {
            this.optimizerStatisticsCollectionOperationId = Objects.requireNonNull(optimizerStatisticsCollectionOperationId);
            return this;
        }
        @CustomType.Setter
        public Builder startTime(String startTime) {
            this.startTime = Objects.requireNonNull(startTime);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder target(String target) {
            this.target = Objects.requireNonNull(target);
            return this;
        }
        @CustomType.Setter
        public Builder tasks(List<GetManagedDatabaseOptimizerStatisticsCollectionOperationTask> tasks) {
            this.tasks = Objects.requireNonNull(tasks);
            return this;
        }
        public Builder tasks(GetManagedDatabaseOptimizerStatisticsCollectionOperationTask... tasks) {
            return tasks(List.of(tasks));
        }
        @CustomType.Setter
        public Builder timedOutCount(Integer timedOutCount) {
            this.timedOutCount = Objects.requireNonNull(timedOutCount);
            return this;
        }
        @CustomType.Setter
        public Builder totalObjectsCount(Integer totalObjectsCount) {
            this.totalObjectsCount = Objects.requireNonNull(totalObjectsCount);
            return this;
        }
        public GetManagedDatabaseOptimizerStatisticsCollectionOperationResult build() {
            final var o = new GetManagedDatabaseOptimizerStatisticsCollectionOperationResult();
            o.completedCount = completedCount;
            o.databases = databases;
            o.durationInSeconds = durationInSeconds;
            o.endTime = endTime;
            o.failedCount = failedCount;
            o.id = id;
            o.inProgressCount = inProgressCount;
            o.jobName = jobName;
            o.managedDatabaseId = managedDatabaseId;
            o.operationName = operationName;
            o.optimizerStatisticsCollectionOperationId = optimizerStatisticsCollectionOperationId;
            o.startTime = startTime;
            o.status = status;
            o.target = target;
            o.tasks = tasks;
            o.timedOutCount = timedOutCount;
            o.totalObjectsCount = totalObjectsCount;
            return o;
        }
    }
}