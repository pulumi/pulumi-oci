// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmTraces.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTraceSpanSummaryServiceSummary {
    /**
     * @return Number of spans with errors for serviceName in the trace.
     * 
     */
    private String errorSpans;
    /**
     * @return Name associated with the service.
     * 
     */
    private String spanServiceName;
    /**
     * @return Number of spans for serviceName in the trace.
     * 
     */
    private String totalSpans;

    private GetTraceSpanSummaryServiceSummary() {}
    /**
     * @return Number of spans with errors for serviceName in the trace.
     * 
     */
    public String errorSpans() {
        return this.errorSpans;
    }
    /**
     * @return Name associated with the service.
     * 
     */
    public String spanServiceName() {
        return this.spanServiceName;
    }
    /**
     * @return Number of spans for serviceName in the trace.
     * 
     */
    public String totalSpans() {
        return this.totalSpans;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTraceSpanSummaryServiceSummary defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String errorSpans;
        private String spanServiceName;
        private String totalSpans;
        public Builder() {}
        public Builder(GetTraceSpanSummaryServiceSummary defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.errorSpans = defaults.errorSpans;
    	      this.spanServiceName = defaults.spanServiceName;
    	      this.totalSpans = defaults.totalSpans;
        }

        @CustomType.Setter
        public Builder errorSpans(String errorSpans) {
            if (errorSpans == null) {
              throw new MissingRequiredPropertyException("GetTraceSpanSummaryServiceSummary", "errorSpans");
            }
            this.errorSpans = errorSpans;
            return this;
        }
        @CustomType.Setter
        public Builder spanServiceName(String spanServiceName) {
            if (spanServiceName == null) {
              throw new MissingRequiredPropertyException("GetTraceSpanSummaryServiceSummary", "spanServiceName");
            }
            this.spanServiceName = spanServiceName;
            return this;
        }
        @CustomType.Setter
        public Builder totalSpans(String totalSpans) {
            if (totalSpans == null) {
              throw new MissingRequiredPropertyException("GetTraceSpanSummaryServiceSummary", "totalSpans");
            }
            this.totalSpans = totalSpans;
            return this;
        }
        public GetTraceSpanSummaryServiceSummary build() {
            final var _resultValue = new GetTraceSpanSummaryServiceSummary();
            _resultValue.errorSpans = errorSpans;
            _resultValue.spanServiceName = spanServiceName;
            _resultValue.totalSpans = totalSpans;
            return _resultValue;
        }
    }
}
