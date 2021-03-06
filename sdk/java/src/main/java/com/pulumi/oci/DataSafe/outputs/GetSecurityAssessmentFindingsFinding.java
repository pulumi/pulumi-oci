// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentFindingsFindingReference;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityAssessmentFindingsFinding {
    /**
     * @return The OCID of the assessment that generated this finding.
     * 
     */
    private final String assessmentId;
    /**
     * @return The details of the finding. Provides detailed information to explain the finding summary, typically results from the assessed database, followed by any recommendations for changes.
     * 
     */
    private final List<String> details;
    /**
     * @return The unique finding key. This is a system-generated identifier. To get the finding key for a finding, use ListFindings.
     * 
     */
    private final String key;
    /**
     * @return Provides information on whether the finding is related to a CIS Oracle Database Benchmark recommendation, a STIG rule, or a GDPR Article/Recital.
     * 
     */
    private final List<GetSecurityAssessmentFindingsFindingReference> references;
    /**
     * @return The explanation of the issue in this finding. It explains the reason for the rule and, if a risk is reported, it may also explain the recommended actions for remediation.
     * 
     */
    private final String remarks;
    /**
     * @return A filter to return only findings of a particular risk level.
     * 
     */
    private final String severity;
    /**
     * @return The brief summary of the finding. When the finding is informational, the summary typically reports only the number of data elements that were examined.
     * 
     */
    private final String summary;
    /**
     * @return The OCID of the target database.
     * 
     */
    private final String targetId;
    /**
     * @return The short title for the finding.
     * 
     */
    private final String title;

    @CustomType.Constructor
    private GetSecurityAssessmentFindingsFinding(
        @CustomType.Parameter("assessmentId") String assessmentId,
        @CustomType.Parameter("details") List<String> details,
        @CustomType.Parameter("key") String key,
        @CustomType.Parameter("references") List<GetSecurityAssessmentFindingsFindingReference> references,
        @CustomType.Parameter("remarks") String remarks,
        @CustomType.Parameter("severity") String severity,
        @CustomType.Parameter("summary") String summary,
        @CustomType.Parameter("targetId") String targetId,
        @CustomType.Parameter("title") String title) {
        this.assessmentId = assessmentId;
        this.details = details;
        this.key = key;
        this.references = references;
        this.remarks = remarks;
        this.severity = severity;
        this.summary = summary;
        this.targetId = targetId;
        this.title = title;
    }

    /**
     * @return The OCID of the assessment that generated this finding.
     * 
     */
    public String assessmentId() {
        return this.assessmentId;
    }
    /**
     * @return The details of the finding. Provides detailed information to explain the finding summary, typically results from the assessed database, followed by any recommendations for changes.
     * 
     */
    public List<String> details() {
        return this.details;
    }
    /**
     * @return The unique finding key. This is a system-generated identifier. To get the finding key for a finding, use ListFindings.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return Provides information on whether the finding is related to a CIS Oracle Database Benchmark recommendation, a STIG rule, or a GDPR Article/Recital.
     * 
     */
    public List<GetSecurityAssessmentFindingsFindingReference> references() {
        return this.references;
    }
    /**
     * @return The explanation of the issue in this finding. It explains the reason for the rule and, if a risk is reported, it may also explain the recommended actions for remediation.
     * 
     */
    public String remarks() {
        return this.remarks;
    }
    /**
     * @return A filter to return only findings of a particular risk level.
     * 
     */
    public String severity() {
        return this.severity;
    }
    /**
     * @return The brief summary of the finding. When the finding is informational, the summary typically reports only the number of data elements that were examined.
     * 
     */
    public String summary() {
        return this.summary;
    }
    /**
     * @return The OCID of the target database.
     * 
     */
    public String targetId() {
        return this.targetId;
    }
    /**
     * @return The short title for the finding.
     * 
     */
    public String title() {
        return this.title;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityAssessmentFindingsFinding defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String assessmentId;
        private List<String> details;
        private String key;
        private List<GetSecurityAssessmentFindingsFindingReference> references;
        private String remarks;
        private String severity;
        private String summary;
        private String targetId;
        private String title;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSecurityAssessmentFindingsFinding defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.assessmentId = defaults.assessmentId;
    	      this.details = defaults.details;
    	      this.key = defaults.key;
    	      this.references = defaults.references;
    	      this.remarks = defaults.remarks;
    	      this.severity = defaults.severity;
    	      this.summary = defaults.summary;
    	      this.targetId = defaults.targetId;
    	      this.title = defaults.title;
        }

        public Builder assessmentId(String assessmentId) {
            this.assessmentId = Objects.requireNonNull(assessmentId);
            return this;
        }
        public Builder details(List<String> details) {
            this.details = Objects.requireNonNull(details);
            return this;
        }
        public Builder details(String... details) {
            return details(List.of(details));
        }
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        public Builder references(List<GetSecurityAssessmentFindingsFindingReference> references) {
            this.references = Objects.requireNonNull(references);
            return this;
        }
        public Builder references(GetSecurityAssessmentFindingsFindingReference... references) {
            return references(List.of(references));
        }
        public Builder remarks(String remarks) {
            this.remarks = Objects.requireNonNull(remarks);
            return this;
        }
        public Builder severity(String severity) {
            this.severity = Objects.requireNonNull(severity);
            return this;
        }
        public Builder summary(String summary) {
            this.summary = Objects.requireNonNull(summary);
            return this;
        }
        public Builder targetId(String targetId) {
            this.targetId = Objects.requireNonNull(targetId);
            return this;
        }
        public Builder title(String title) {
            this.title = Objects.requireNonNull(title);
            return this;
        }        public GetSecurityAssessmentFindingsFinding build() {
            return new GetSecurityAssessmentFindingsFinding(assessmentId, details, key, references, remarks, severity, summary, targetId, title);
        }
    }
}
