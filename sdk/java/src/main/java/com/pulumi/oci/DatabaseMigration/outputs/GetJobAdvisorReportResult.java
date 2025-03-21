// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseMigration.outputs.GetJobAdvisorReportReportLocationDetail;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetJobAdvisorReportResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String jobId;
    /**
     * @return Number of Fatal results in the advisor report.
     * 
     */
    private Integer numberOfFatal;
    /**
     * @return Number of Fatal Blocker results in the advisor report.
     * 
     */
    private Integer numberOfFatalBlockers;
    /**
     * @return Number of Informational results in the advisor report.
     * 
     */
    private Integer numberOfInformationalResults;
    /**
     * @return Number of Warning results in the advisor report.
     * 
     */
    private Integer numberOfWarnings;
    /**
     * @return Details to access Premigration Advisor report.
     * 
     */
    private List<GetJobAdvisorReportReportLocationDetail> reportLocationDetails;
    /**
     * @return Premigration Advisor result.
     * 
     */
    private String result;

    private GetJobAdvisorReportResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String jobId() {
        return this.jobId;
    }
    /**
     * @return Number of Fatal results in the advisor report.
     * 
     */
    public Integer numberOfFatal() {
        return this.numberOfFatal;
    }
    /**
     * @return Number of Fatal Blocker results in the advisor report.
     * 
     */
    public Integer numberOfFatalBlockers() {
        return this.numberOfFatalBlockers;
    }
    /**
     * @return Number of Informational results in the advisor report.
     * 
     */
    public Integer numberOfInformationalResults() {
        return this.numberOfInformationalResults;
    }
    /**
     * @return Number of Warning results in the advisor report.
     * 
     */
    public Integer numberOfWarnings() {
        return this.numberOfWarnings;
    }
    /**
     * @return Details to access Premigration Advisor report.
     * 
     */
    public List<GetJobAdvisorReportReportLocationDetail> reportLocationDetails() {
        return this.reportLocationDetails;
    }
    /**
     * @return Premigration Advisor result.
     * 
     */
    public String result() {
        return this.result;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetJobAdvisorReportResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private String jobId;
        private Integer numberOfFatal;
        private Integer numberOfFatalBlockers;
        private Integer numberOfInformationalResults;
        private Integer numberOfWarnings;
        private List<GetJobAdvisorReportReportLocationDetail> reportLocationDetails;
        private String result;
        public Builder() {}
        public Builder(GetJobAdvisorReportResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.jobId = defaults.jobId;
    	      this.numberOfFatal = defaults.numberOfFatal;
    	      this.numberOfFatalBlockers = defaults.numberOfFatalBlockers;
    	      this.numberOfInformationalResults = defaults.numberOfInformationalResults;
    	      this.numberOfWarnings = defaults.numberOfWarnings;
    	      this.reportLocationDetails = defaults.reportLocationDetails;
    	      this.result = defaults.result;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetJobAdvisorReportResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder jobId(String jobId) {
            if (jobId == null) {
              throw new MissingRequiredPropertyException("GetJobAdvisorReportResult", "jobId");
            }
            this.jobId = jobId;
            return this;
        }
        @CustomType.Setter
        public Builder numberOfFatal(Integer numberOfFatal) {
            if (numberOfFatal == null) {
              throw new MissingRequiredPropertyException("GetJobAdvisorReportResult", "numberOfFatal");
            }
            this.numberOfFatal = numberOfFatal;
            return this;
        }
        @CustomType.Setter
        public Builder numberOfFatalBlockers(Integer numberOfFatalBlockers) {
            if (numberOfFatalBlockers == null) {
              throw new MissingRequiredPropertyException("GetJobAdvisorReportResult", "numberOfFatalBlockers");
            }
            this.numberOfFatalBlockers = numberOfFatalBlockers;
            return this;
        }
        @CustomType.Setter
        public Builder numberOfInformationalResults(Integer numberOfInformationalResults) {
            if (numberOfInformationalResults == null) {
              throw new MissingRequiredPropertyException("GetJobAdvisorReportResult", "numberOfInformationalResults");
            }
            this.numberOfInformationalResults = numberOfInformationalResults;
            return this;
        }
        @CustomType.Setter
        public Builder numberOfWarnings(Integer numberOfWarnings) {
            if (numberOfWarnings == null) {
              throw new MissingRequiredPropertyException("GetJobAdvisorReportResult", "numberOfWarnings");
            }
            this.numberOfWarnings = numberOfWarnings;
            return this;
        }
        @CustomType.Setter
        public Builder reportLocationDetails(List<GetJobAdvisorReportReportLocationDetail> reportLocationDetails) {
            if (reportLocationDetails == null) {
              throw new MissingRequiredPropertyException("GetJobAdvisorReportResult", "reportLocationDetails");
            }
            this.reportLocationDetails = reportLocationDetails;
            return this;
        }
        public Builder reportLocationDetails(GetJobAdvisorReportReportLocationDetail... reportLocationDetails) {
            return reportLocationDetails(List.of(reportLocationDetails));
        }
        @CustomType.Setter
        public Builder result(String result) {
            if (result == null) {
              throw new MissingRequiredPropertyException("GetJobAdvisorReportResult", "result");
            }
            this.result = result;
            return this;
        }
        public GetJobAdvisorReportResult build() {
            final var _resultValue = new GetJobAdvisorReportResult();
            _resultValue.id = id;
            _resultValue.jobId = jobId;
            _resultValue.numberOfFatal = numberOfFatal;
            _resultValue.numberOfFatalBlockers = numberOfFatalBlockers;
            _resultValue.numberOfInformationalResults = numberOfInformationalResults;
            _resultValue.numberOfWarnings = numberOfWarnings;
            _resultValue.reportLocationDetails = reportLocationDetails;
            _resultValue.result = result;
            return _resultValue;
        }
    }
}
