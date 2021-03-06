// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetJobRunLogDetail {
    /**
     * @return The log group id for where log objects will be for job runs.
     * 
     */
    private final String logGroupId;
    /**
     * @return The log id of the log object the job run logs will be shipped to.
     * 
     */
    private final String logId;

    @CustomType.Constructor
    private GetJobRunLogDetail(
        @CustomType.Parameter("logGroupId") String logGroupId,
        @CustomType.Parameter("logId") String logId) {
        this.logGroupId = logGroupId;
        this.logId = logId;
    }

    /**
     * @return The log group id for where log objects will be for job runs.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }
    /**
     * @return The log id of the log object the job run logs will be shipped to.
     * 
     */
    public String logId() {
        return this.logId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetJobRunLogDetail defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String logGroupId;
        private String logId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetJobRunLogDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        public Builder logGroupId(String logGroupId) {
            this.logGroupId = Objects.requireNonNull(logGroupId);
            return this;
        }
        public Builder logId(String logId) {
            this.logId = Objects.requireNonNull(logId);
            return this;
        }        public GetJobRunLogDetail build() {
            return new GetJobRunLogDetail(logGroupId, logId);
        }
    }
}
