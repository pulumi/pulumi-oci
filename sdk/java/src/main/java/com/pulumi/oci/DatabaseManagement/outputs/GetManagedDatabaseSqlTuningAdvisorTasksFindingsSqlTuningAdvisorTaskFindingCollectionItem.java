// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseSqlTuningAdvisorTasksFindingsSqlTuningAdvisorTaskFindingCollectionItem {
    /**
     * @return The time benefit (in seconds) for the highest-rated finding for this object.
     * 
     */
    private Double dbTimeBenefit;
    /**
     * @return Indicates whether an alternative execution plan was reported for this SQL statement.
     * 
     */
    private Boolean isAlternativePlanFindingPresent;
    /**
     * @return Indicates whether there is an error in this SQL statement.
     * 
     */
    private Boolean isErrorFindingPresent;
    /**
     * @return Indicates whether an index recommendation was reported for this SQL statement.
     * 
     */
    private Boolean isIndexFindingPresent;
    /**
     * @return Indicates whether a miscellaneous finding was reported for this SQL statement.
     * 
     */
    private Boolean isMiscellaneousFindingPresent;
    /**
     * @return Indicates whether a restructure SQL recommendation was reported for this SQL statement.
     * 
     */
    private Boolean isRestructureSqlFindingPresent;
    /**
     * @return Indicates whether a SQL Profile recommendation has been implemented for this SQL statement.
     * 
     */
    private Boolean isSqlProfileFindingImplemented;
    /**
     * @return Indicates whether a SQL Profile recommendation was reported for this SQL statement.
     * 
     */
    private Boolean isSqlProfileFindingPresent;
    /**
     * @return Indicates whether a statistics recommendation was reported for this SQL statement.
     * 
     */
    private Boolean isStatsFindingPresent;
    /**
     * @return Indicates whether the task timed out.
     * 
     */
    private Boolean isTimeoutFindingPresent;
    /**
     * @return The parsing schema of the object.
     * 
     */
    private String parsingSchema;
    /**
     * @return The per-execution percentage benefit.
     * 
     */
    private Integer perExecutionPercentage;
    /**
     * @return The unique key of this SQL statement.
     * 
     */
    private String sqlKey;
    /**
     * @return The text of the SQL statement.
     * 
     */
    private String sqlText;
    /**
     * @return The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String sqlTuningAdvisorTaskId;
    /**
     * @return The execution id of the analyzed SQL object. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String sqlTuningAdvisorTaskObjectExecutionId;
    /**
     * @return The key of the object to which these recommendations apply. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String sqlTuningAdvisorTaskObjectId;

    private GetManagedDatabaseSqlTuningAdvisorTasksFindingsSqlTuningAdvisorTaskFindingCollectionItem() {}
    /**
     * @return The time benefit (in seconds) for the highest-rated finding for this object.
     * 
     */
    public Double dbTimeBenefit() {
        return this.dbTimeBenefit;
    }
    /**
     * @return Indicates whether an alternative execution plan was reported for this SQL statement.
     * 
     */
    public Boolean isAlternativePlanFindingPresent() {
        return this.isAlternativePlanFindingPresent;
    }
    /**
     * @return Indicates whether there is an error in this SQL statement.
     * 
     */
    public Boolean isErrorFindingPresent() {
        return this.isErrorFindingPresent;
    }
    /**
     * @return Indicates whether an index recommendation was reported for this SQL statement.
     * 
     */
    public Boolean isIndexFindingPresent() {
        return this.isIndexFindingPresent;
    }
    /**
     * @return Indicates whether a miscellaneous finding was reported for this SQL statement.
     * 
     */
    public Boolean isMiscellaneousFindingPresent() {
        return this.isMiscellaneousFindingPresent;
    }
    /**
     * @return Indicates whether a restructure SQL recommendation was reported for this SQL statement.
     * 
     */
    public Boolean isRestructureSqlFindingPresent() {
        return this.isRestructureSqlFindingPresent;
    }
    /**
     * @return Indicates whether a SQL Profile recommendation has been implemented for this SQL statement.
     * 
     */
    public Boolean isSqlProfileFindingImplemented() {
        return this.isSqlProfileFindingImplemented;
    }
    /**
     * @return Indicates whether a SQL Profile recommendation was reported for this SQL statement.
     * 
     */
    public Boolean isSqlProfileFindingPresent() {
        return this.isSqlProfileFindingPresent;
    }
    /**
     * @return Indicates whether a statistics recommendation was reported for this SQL statement.
     * 
     */
    public Boolean isStatsFindingPresent() {
        return this.isStatsFindingPresent;
    }
    /**
     * @return Indicates whether the task timed out.
     * 
     */
    public Boolean isTimeoutFindingPresent() {
        return this.isTimeoutFindingPresent;
    }
    /**
     * @return The parsing schema of the object.
     * 
     */
    public String parsingSchema() {
        return this.parsingSchema;
    }
    /**
     * @return The per-execution percentage benefit.
     * 
     */
    public Integer perExecutionPercentage() {
        return this.perExecutionPercentage;
    }
    /**
     * @return The unique key of this SQL statement.
     * 
     */
    public String sqlKey() {
        return this.sqlKey;
    }
    /**
     * @return The text of the SQL statement.
     * 
     */
    public String sqlText() {
        return this.sqlText;
    }
    /**
     * @return The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String sqlTuningAdvisorTaskId() {
        return this.sqlTuningAdvisorTaskId;
    }
    /**
     * @return The execution id of the analyzed SQL object. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String sqlTuningAdvisorTaskObjectExecutionId() {
        return this.sqlTuningAdvisorTaskObjectExecutionId;
    }
    /**
     * @return The key of the object to which these recommendations apply. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String sqlTuningAdvisorTaskObjectId() {
        return this.sqlTuningAdvisorTaskObjectId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksFindingsSqlTuningAdvisorTaskFindingCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double dbTimeBenefit;
        private Boolean isAlternativePlanFindingPresent;
        private Boolean isErrorFindingPresent;
        private Boolean isIndexFindingPresent;
        private Boolean isMiscellaneousFindingPresent;
        private Boolean isRestructureSqlFindingPresent;
        private Boolean isSqlProfileFindingImplemented;
        private Boolean isSqlProfileFindingPresent;
        private Boolean isStatsFindingPresent;
        private Boolean isTimeoutFindingPresent;
        private String parsingSchema;
        private Integer perExecutionPercentage;
        private String sqlKey;
        private String sqlText;
        private String sqlTuningAdvisorTaskId;
        private String sqlTuningAdvisorTaskObjectExecutionId;
        private String sqlTuningAdvisorTaskObjectId;
        public Builder() {}
        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksFindingsSqlTuningAdvisorTaskFindingCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbTimeBenefit = defaults.dbTimeBenefit;
    	      this.isAlternativePlanFindingPresent = defaults.isAlternativePlanFindingPresent;
    	      this.isErrorFindingPresent = defaults.isErrorFindingPresent;
    	      this.isIndexFindingPresent = defaults.isIndexFindingPresent;
    	      this.isMiscellaneousFindingPresent = defaults.isMiscellaneousFindingPresent;
    	      this.isRestructureSqlFindingPresent = defaults.isRestructureSqlFindingPresent;
    	      this.isSqlProfileFindingImplemented = defaults.isSqlProfileFindingImplemented;
    	      this.isSqlProfileFindingPresent = defaults.isSqlProfileFindingPresent;
    	      this.isStatsFindingPresent = defaults.isStatsFindingPresent;
    	      this.isTimeoutFindingPresent = defaults.isTimeoutFindingPresent;
    	      this.parsingSchema = defaults.parsingSchema;
    	      this.perExecutionPercentage = defaults.perExecutionPercentage;
    	      this.sqlKey = defaults.sqlKey;
    	      this.sqlText = defaults.sqlText;
    	      this.sqlTuningAdvisorTaskId = defaults.sqlTuningAdvisorTaskId;
    	      this.sqlTuningAdvisorTaskObjectExecutionId = defaults.sqlTuningAdvisorTaskObjectExecutionId;
    	      this.sqlTuningAdvisorTaskObjectId = defaults.sqlTuningAdvisorTaskObjectId;
        }

        @CustomType.Setter
        public Builder dbTimeBenefit(Double dbTimeBenefit) {
            this.dbTimeBenefit = Objects.requireNonNull(dbTimeBenefit);
            return this;
        }
        @CustomType.Setter
        public Builder isAlternativePlanFindingPresent(Boolean isAlternativePlanFindingPresent) {
            this.isAlternativePlanFindingPresent = Objects.requireNonNull(isAlternativePlanFindingPresent);
            return this;
        }
        @CustomType.Setter
        public Builder isErrorFindingPresent(Boolean isErrorFindingPresent) {
            this.isErrorFindingPresent = Objects.requireNonNull(isErrorFindingPresent);
            return this;
        }
        @CustomType.Setter
        public Builder isIndexFindingPresent(Boolean isIndexFindingPresent) {
            this.isIndexFindingPresent = Objects.requireNonNull(isIndexFindingPresent);
            return this;
        }
        @CustomType.Setter
        public Builder isMiscellaneousFindingPresent(Boolean isMiscellaneousFindingPresent) {
            this.isMiscellaneousFindingPresent = Objects.requireNonNull(isMiscellaneousFindingPresent);
            return this;
        }
        @CustomType.Setter
        public Builder isRestructureSqlFindingPresent(Boolean isRestructureSqlFindingPresent) {
            this.isRestructureSqlFindingPresent = Objects.requireNonNull(isRestructureSqlFindingPresent);
            return this;
        }
        @CustomType.Setter
        public Builder isSqlProfileFindingImplemented(Boolean isSqlProfileFindingImplemented) {
            this.isSqlProfileFindingImplemented = Objects.requireNonNull(isSqlProfileFindingImplemented);
            return this;
        }
        @CustomType.Setter
        public Builder isSqlProfileFindingPresent(Boolean isSqlProfileFindingPresent) {
            this.isSqlProfileFindingPresent = Objects.requireNonNull(isSqlProfileFindingPresent);
            return this;
        }
        @CustomType.Setter
        public Builder isStatsFindingPresent(Boolean isStatsFindingPresent) {
            this.isStatsFindingPresent = Objects.requireNonNull(isStatsFindingPresent);
            return this;
        }
        @CustomType.Setter
        public Builder isTimeoutFindingPresent(Boolean isTimeoutFindingPresent) {
            this.isTimeoutFindingPresent = Objects.requireNonNull(isTimeoutFindingPresent);
            return this;
        }
        @CustomType.Setter
        public Builder parsingSchema(String parsingSchema) {
            this.parsingSchema = Objects.requireNonNull(parsingSchema);
            return this;
        }
        @CustomType.Setter
        public Builder perExecutionPercentage(Integer perExecutionPercentage) {
            this.perExecutionPercentage = Objects.requireNonNull(perExecutionPercentage);
            return this;
        }
        @CustomType.Setter
        public Builder sqlKey(String sqlKey) {
            this.sqlKey = Objects.requireNonNull(sqlKey);
            return this;
        }
        @CustomType.Setter
        public Builder sqlText(String sqlText) {
            this.sqlText = Objects.requireNonNull(sqlText);
            return this;
        }
        @CustomType.Setter
        public Builder sqlTuningAdvisorTaskId(String sqlTuningAdvisorTaskId) {
            this.sqlTuningAdvisorTaskId = Objects.requireNonNull(sqlTuningAdvisorTaskId);
            return this;
        }
        @CustomType.Setter
        public Builder sqlTuningAdvisorTaskObjectExecutionId(String sqlTuningAdvisorTaskObjectExecutionId) {
            this.sqlTuningAdvisorTaskObjectExecutionId = Objects.requireNonNull(sqlTuningAdvisorTaskObjectExecutionId);
            return this;
        }
        @CustomType.Setter
        public Builder sqlTuningAdvisorTaskObjectId(String sqlTuningAdvisorTaskObjectId) {
            this.sqlTuningAdvisorTaskObjectId = Objects.requireNonNull(sqlTuningAdvisorTaskObjectId);
            return this;
        }
        public GetManagedDatabaseSqlTuningAdvisorTasksFindingsSqlTuningAdvisorTaskFindingCollectionItem build() {
            final var o = new GetManagedDatabaseSqlTuningAdvisorTasksFindingsSqlTuningAdvisorTaskFindingCollectionItem();
            o.dbTimeBenefit = dbTimeBenefit;
            o.isAlternativePlanFindingPresent = isAlternativePlanFindingPresent;
            o.isErrorFindingPresent = isErrorFindingPresent;
            o.isIndexFindingPresent = isIndexFindingPresent;
            o.isMiscellaneousFindingPresent = isMiscellaneousFindingPresent;
            o.isRestructureSqlFindingPresent = isRestructureSqlFindingPresent;
            o.isSqlProfileFindingImplemented = isSqlProfileFindingImplemented;
            o.isSqlProfileFindingPresent = isSqlProfileFindingPresent;
            o.isStatsFindingPresent = isStatsFindingPresent;
            o.isTimeoutFindingPresent = isTimeoutFindingPresent;
            o.parsingSchema = parsingSchema;
            o.perExecutionPercentage = perExecutionPercentage;
            o.sqlKey = sqlKey;
            o.sqlText = sqlText;
            o.sqlTuningAdvisorTaskId = sqlTuningAdvisorTaskId;
            o.sqlTuningAdvisorTaskObjectExecutionId = sqlTuningAdvisorTaskObjectExecutionId;
            o.sqlTuningAdvisorTaskObjectId = sqlTuningAdvisorTaskObjectId;
            return o;
        }
    }
}