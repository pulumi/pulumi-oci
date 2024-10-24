// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetReportContentArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetReportContentArgs Empty = new GetReportContentArgs();

    /**
     * Unique report identifier
     * 
     */
    @Import(name="reportId", required=true)
    private Output<String> reportId;

    /**
     * @return Unique report identifier
     * 
     */
    public Output<String> reportId() {
        return this.reportId;
    }

    private GetReportContentArgs() {}

    private GetReportContentArgs(GetReportContentArgs $) {
        this.reportId = $.reportId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetReportContentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetReportContentArgs $;

        public Builder() {
            $ = new GetReportContentArgs();
        }

        public Builder(GetReportContentArgs defaults) {
            $ = new GetReportContentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param reportId Unique report identifier
         * 
         * @return builder
         * 
         */
        public Builder reportId(Output<String> reportId) {
            $.reportId = reportId;
            return this;
        }

        /**
         * @param reportId Unique report identifier
         * 
         * @return builder
         * 
         */
        public Builder reportId(String reportId) {
            return reportId(Output.of(reportId));
        }

        public GetReportContentArgs build() {
            if ($.reportId == null) {
                throw new MissingRequiredPropertyException("GetReportContentArgs", "reportId");
            }
            return $;
        }
    }

}
