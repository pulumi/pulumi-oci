// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemDatabase;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemReport;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItem {
    /**
     * @return The summary of the Managed Database resource.
     * 
     */
    private List<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemDatabase> databases;
    /**
     * @return The errors in the Optimizer Statistics Advisor execution, if any.
     * 
     */
    private String errorMessage;
    /**
     * @return The name of the Optimizer Statistics Advisor execution.
     * 
     */
    private String executionName;
    /**
     * @return The list of findings for the rule.
     * 
     */
    private Integer findings;
    /**
     * @return A report that includes the rules, findings, recommendations, and actions discovered during the execution of the Optimizer Statistics Advisor.
     * 
     */
    private List<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemReport> reports;
    /**
     * @return The status of the Optimizer Statistics Advisor execution.
     * 
     */
    private String status;
    /**
     * @return The Optimizer Statistics Advisor execution status message, if any.
     * 
     */
    private String statusMessage;
    /**
     * @return The name of the Optimizer Statistics Advisor task.
     * 
     */
    private String taskName;
    /**
     * @return The end time of the time range to retrieve the Optimizer Statistics Advisor execution of a Managed Database in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
     * 
     */
    private String timeEnd;
    /**
     * @return The start time of the time range to retrieve the Optimizer Statistics Advisor execution of a Managed Database in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
     * 
     */
    private String timeStart;

    private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItem() {}
    /**
     * @return The summary of the Managed Database resource.
     * 
     */
    public List<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemDatabase> databases() {
        return this.databases;
    }
    /**
     * @return The errors in the Optimizer Statistics Advisor execution, if any.
     * 
     */
    public String errorMessage() {
        return this.errorMessage;
    }
    /**
     * @return The name of the Optimizer Statistics Advisor execution.
     * 
     */
    public String executionName() {
        return this.executionName;
    }
    /**
     * @return The list of findings for the rule.
     * 
     */
    public Integer findings() {
        return this.findings;
    }
    /**
     * @return A report that includes the rules, findings, recommendations, and actions discovered during the execution of the Optimizer Statistics Advisor.
     * 
     */
    public List<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemReport> reports() {
        return this.reports;
    }
    /**
     * @return The status of the Optimizer Statistics Advisor execution.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The Optimizer Statistics Advisor execution status message, if any.
     * 
     */
    public String statusMessage() {
        return this.statusMessage;
    }
    /**
     * @return The name of the Optimizer Statistics Advisor task.
     * 
     */
    public String taskName() {
        return this.taskName;
    }
    /**
     * @return The end time of the time range to retrieve the Optimizer Statistics Advisor execution of a Managed Database in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
     * 
     */
    public String timeEnd() {
        return this.timeEnd;
    }
    /**
     * @return The start time of the time range to retrieve the Optimizer Statistics Advisor execution of a Managed Database in UTC in ISO-8601 format, which is &#34;yyyy-MM-dd&#39;T&#39;hh:mm:ss.sss&#39;Z&#39;&#34;.
     * 
     */
    public String timeStart() {
        return this.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemDatabase> databases;
        private String errorMessage;
        private String executionName;
        private Integer findings;
        private List<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemReport> reports;
        private String status;
        private String statusMessage;
        private String taskName;
        private String timeEnd;
        private String timeStart;
        public Builder() {}
        public Builder(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databases = defaults.databases;
    	      this.errorMessage = defaults.errorMessage;
    	      this.executionName = defaults.executionName;
    	      this.findings = defaults.findings;
    	      this.reports = defaults.reports;
    	      this.status = defaults.status;
    	      this.statusMessage = defaults.statusMessage;
    	      this.taskName = defaults.taskName;
    	      this.timeEnd = defaults.timeEnd;
    	      this.timeStart = defaults.timeStart;
        }

        @CustomType.Setter
        public Builder databases(List<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemDatabase> databases) {
            this.databases = Objects.requireNonNull(databases);
            return this;
        }
        public Builder databases(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemDatabase... databases) {
            return databases(List.of(databases));
        }
        @CustomType.Setter
        public Builder errorMessage(String errorMessage) {
            this.errorMessage = Objects.requireNonNull(errorMessage);
            return this;
        }
        @CustomType.Setter
        public Builder executionName(String executionName) {
            this.executionName = Objects.requireNonNull(executionName);
            return this;
        }
        @CustomType.Setter
        public Builder findings(Integer findings) {
            this.findings = Objects.requireNonNull(findings);
            return this;
        }
        @CustomType.Setter
        public Builder reports(List<GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemReport> reports) {
            this.reports = Objects.requireNonNull(reports);
            return this;
        }
        public Builder reports(GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemReport... reports) {
            return reports(List.of(reports));
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder statusMessage(String statusMessage) {
            this.statusMessage = Objects.requireNonNull(statusMessage);
            return this;
        }
        @CustomType.Setter
        public Builder taskName(String taskName) {
            this.taskName = Objects.requireNonNull(taskName);
            return this;
        }
        @CustomType.Setter
        public Builder timeEnd(String timeEnd) {
            this.timeEnd = Objects.requireNonNull(timeEnd);
            return this;
        }
        @CustomType.Setter
        public Builder timeStart(String timeStart) {
            this.timeStart = Objects.requireNonNull(timeStart);
            return this;
        }
        public GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItem build() {
            final var o = new GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItem();
            o.databases = databases;
            o.errorMessage = errorMessage;
            o.executionName = executionName;
            o.findings = findings;
            o.reports = reports;
            o.status = status;
            o.statusMessage = statusMessage;
            o.taskName = taskName;
            o.timeEnd = timeEnd;
            o.timeStart = timeStart;
            return o;
        }
    }
}