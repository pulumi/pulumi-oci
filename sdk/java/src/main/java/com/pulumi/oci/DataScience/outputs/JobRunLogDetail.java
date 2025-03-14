// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class JobRunLogDetail {
    /**
     * @return The log group id for where log objects will be for job runs.
     * 
     */
    private @Nullable String logGroupId;
    /**
     * @return The log id of the log object the job run logs will be shipped to.
     * 
     */
    private @Nullable String logId;

    private JobRunLogDetail() {}
    /**
     * @return The log group id for where log objects will be for job runs.
     * 
     */
    public Optional<String> logGroupId() {
        return Optional.ofNullable(this.logGroupId);
    }
    /**
     * @return The log id of the log object the job run logs will be shipped to.
     * 
     */
    public Optional<String> logId() {
        return Optional.ofNullable(this.logId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(JobRunLogDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String logGroupId;
        private @Nullable String logId;
        public Builder() {}
        public Builder(JobRunLogDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        @CustomType.Setter
        public Builder logGroupId(@Nullable String logGroupId) {

            this.logGroupId = logGroupId;
            return this;
        }
        @CustomType.Setter
        public Builder logId(@Nullable String logId) {

            this.logId = logId;
            return this;
        }
        public JobRunLogDetail build() {
            final var _resultValue = new JobRunLogDetail();
            _resultValue.logGroupId = logGroupId;
            _resultValue.logId = logId;
            return _resultValue;
        }
    }
}
