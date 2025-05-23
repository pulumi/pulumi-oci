// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiValidationValidationDetailSrc;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiValidationValidationDetail {
    /**
     * @return Description of the warning/error.
     * 
     */
    private String msg;
    /**
     * @return Severity of the issue.
     * 
     */
    private String severity;
    /**
     * @return Position of the issue in the specification file (line, column).
     * 
     */
    private List<GetApiValidationValidationDetailSrc> srcs;

    private GetApiValidationValidationDetail() {}
    /**
     * @return Description of the warning/error.
     * 
     */
    public String msg() {
        return this.msg;
    }
    /**
     * @return Severity of the issue.
     * 
     */
    public String severity() {
        return this.severity;
    }
    /**
     * @return Position of the issue in the specification file (line, column).
     * 
     */
    public List<GetApiValidationValidationDetailSrc> srcs() {
        return this.srcs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiValidationValidationDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String msg;
        private String severity;
        private List<GetApiValidationValidationDetailSrc> srcs;
        public Builder() {}
        public Builder(GetApiValidationValidationDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.msg = defaults.msg;
    	      this.severity = defaults.severity;
    	      this.srcs = defaults.srcs;
        }

        @CustomType.Setter
        public Builder msg(String msg) {
            if (msg == null) {
              throw new MissingRequiredPropertyException("GetApiValidationValidationDetail", "msg");
            }
            this.msg = msg;
            return this;
        }
        @CustomType.Setter
        public Builder severity(String severity) {
            if (severity == null) {
              throw new MissingRequiredPropertyException("GetApiValidationValidationDetail", "severity");
            }
            this.severity = severity;
            return this;
        }
        @CustomType.Setter
        public Builder srcs(List<GetApiValidationValidationDetailSrc> srcs) {
            if (srcs == null) {
              throw new MissingRequiredPropertyException("GetApiValidationValidationDetail", "srcs");
            }
            this.srcs = srcs;
            return this;
        }
        public Builder srcs(GetApiValidationValidationDetailSrc... srcs) {
            return srcs(List.of(srcs));
        }
        public GetApiValidationValidationDetail build() {
            final var _resultValue = new GetApiValidationValidationDetail();
            _resultValue.msg = msg;
            _resultValue.severity = severity;
            _resultValue.srcs = srcs;
            return _resultValue;
        }
    }
}
