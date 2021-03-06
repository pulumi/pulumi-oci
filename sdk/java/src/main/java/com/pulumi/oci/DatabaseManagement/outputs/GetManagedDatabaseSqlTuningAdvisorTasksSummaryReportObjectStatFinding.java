// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding {
    /**
     * @return Name of the object.
     * 
     */
    private final String object;
    /**
     * @return Numerical representation of the object.
     * 
     */
    private final String objectHashValue;
    /**
     * @return Type of the object.
     * 
     */
    private final String objectType;
    /**
     * @return Type of statistics problem related to the object.
     * 
     */
    private final String problemType;
    /**
     * @return The number of the times the object is referenced within the SQL Tuning advisor task findings.
     * 
     */
    private final Integer referenceCount;
    /**
     * @return Schema of the object.
     * 
     */
    private final String schema;

    @CustomType.Constructor
    private GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding(
        @CustomType.Parameter("object") String object,
        @CustomType.Parameter("objectHashValue") String objectHashValue,
        @CustomType.Parameter("objectType") String objectType,
        @CustomType.Parameter("problemType") String problemType,
        @CustomType.Parameter("referenceCount") Integer referenceCount,
        @CustomType.Parameter("schema") String schema) {
        this.object = object;
        this.objectHashValue = objectHashValue;
        this.objectType = objectType;
        this.problemType = problemType;
        this.referenceCount = referenceCount;
        this.schema = schema;
    }

    /**
     * @return Name of the object.
     * 
     */
    public String object() {
        return this.object;
    }
    /**
     * @return Numerical representation of the object.
     * 
     */
    public String objectHashValue() {
        return this.objectHashValue;
    }
    /**
     * @return Type of the object.
     * 
     */
    public String objectType() {
        return this.objectType;
    }
    /**
     * @return Type of statistics problem related to the object.
     * 
     */
    public String problemType() {
        return this.problemType;
    }
    /**
     * @return The number of the times the object is referenced within the SQL Tuning advisor task findings.
     * 
     */
    public Integer referenceCount() {
        return this.referenceCount;
    }
    /**
     * @return Schema of the object.
     * 
     */
    public String schema() {
        return this.schema;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String object;
        private String objectHashValue;
        private String objectType;
        private String problemType;
        private Integer referenceCount;
        private String schema;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.object = defaults.object;
    	      this.objectHashValue = defaults.objectHashValue;
    	      this.objectType = defaults.objectType;
    	      this.problemType = defaults.problemType;
    	      this.referenceCount = defaults.referenceCount;
    	      this.schema = defaults.schema;
        }

        public Builder object(String object) {
            this.object = Objects.requireNonNull(object);
            return this;
        }
        public Builder objectHashValue(String objectHashValue) {
            this.objectHashValue = Objects.requireNonNull(objectHashValue);
            return this;
        }
        public Builder objectType(String objectType) {
            this.objectType = Objects.requireNonNull(objectType);
            return this;
        }
        public Builder problemType(String problemType) {
            this.problemType = Objects.requireNonNull(problemType);
            return this;
        }
        public Builder referenceCount(Integer referenceCount) {
            this.referenceCount = Objects.requireNonNull(referenceCount);
            return this;
        }
        public Builder schema(String schema) {
            this.schema = Objects.requireNonNull(schema);
            return this;
        }        public GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding build() {
            return new GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding(object, objectHashValue, objectType, problemType, referenceCount, schema);
        }
    }
}
