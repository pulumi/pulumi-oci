// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInvokeRunsRunApplicationLogConfig {
    /**
     * @return The log group id for where log objects will be for Data Flow Runs.
     * 
     */
    private String logGroupId;
    /**
     * @return The log id of the log object the Application Logs of Data Flow Run will be shipped to.
     * 
     */
    private String logId;

    private GetInvokeRunsRunApplicationLogConfig() {}
    /**
     * @return The log group id for where log objects will be for Data Flow Runs.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }
    /**
     * @return The log id of the log object the Application Logs of Data Flow Run will be shipped to.
     * 
     */
    public String logId() {
        return this.logId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInvokeRunsRunApplicationLogConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String logGroupId;
        private String logId;
        public Builder() {}
        public Builder(GetInvokeRunsRunApplicationLogConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        @CustomType.Setter
        public Builder logGroupId(String logGroupId) {
            this.logGroupId = Objects.requireNonNull(logGroupId);
            return this;
        }
        @CustomType.Setter
        public Builder logId(String logId) {
            this.logId = Objects.requireNonNull(logId);
            return this;
        }
        public GetInvokeRunsRunApplicationLogConfig build() {
            final var o = new GetInvokeRunsRunApplicationLogConfig();
            o.logGroupId = logGroupId;
            o.logId = logId;
            return o;
        }
    }
}