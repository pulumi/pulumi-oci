// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentFindingFindingReference;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityAssessmentFindingFinding {
    private String assessmentId;
    private List<String> details;
    private String key;
    private List<GetSecurityAssessmentFindingFindingReference> references;
    private String remarks;
    private String severity;
    private String summary;
    private String targetId;
    private String title;

    private GetSecurityAssessmentFindingFinding() {}
    public String assessmentId() {
        return this.assessmentId;
    }
    public List<String> details() {
        return this.details;
    }
    public String key() {
        return this.key;
    }
    public List<GetSecurityAssessmentFindingFindingReference> references() {
        return this.references;
    }
    public String remarks() {
        return this.remarks;
    }
    public String severity() {
        return this.severity;
    }
    public String summary() {
        return this.summary;
    }
    public String targetId() {
        return this.targetId;
    }
    public String title() {
        return this.title;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityAssessmentFindingFinding defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String assessmentId;
        private List<String> details;
        private String key;
        private List<GetSecurityAssessmentFindingFindingReference> references;
        private String remarks;
        private String severity;
        private String summary;
        private String targetId;
        private String title;
        public Builder() {}
        public Builder(GetSecurityAssessmentFindingFinding defaults) {
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

        @CustomType.Setter
        public Builder assessmentId(String assessmentId) {
            this.assessmentId = Objects.requireNonNull(assessmentId);
            return this;
        }
        @CustomType.Setter
        public Builder details(List<String> details) {
            this.details = Objects.requireNonNull(details);
            return this;
        }
        public Builder details(String... details) {
            return details(List.of(details));
        }
        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        @CustomType.Setter
        public Builder references(List<GetSecurityAssessmentFindingFindingReference> references) {
            this.references = Objects.requireNonNull(references);
            return this;
        }
        public Builder references(GetSecurityAssessmentFindingFindingReference... references) {
            return references(List.of(references));
        }
        @CustomType.Setter
        public Builder remarks(String remarks) {
            this.remarks = Objects.requireNonNull(remarks);
            return this;
        }
        @CustomType.Setter
        public Builder severity(String severity) {
            this.severity = Objects.requireNonNull(severity);
            return this;
        }
        @CustomType.Setter
        public Builder summary(String summary) {
            this.summary = Objects.requireNonNull(summary);
            return this;
        }
        @CustomType.Setter
        public Builder targetId(String targetId) {
            this.targetId = Objects.requireNonNull(targetId);
            return this;
        }
        @CustomType.Setter
        public Builder title(String title) {
            this.title = Objects.requireNonNull(title);
            return this;
        }
        public GetSecurityAssessmentFindingFinding build() {
            final var o = new GetSecurityAssessmentFindingFinding();
            o.assessmentId = assessmentId;
            o.details = details;
            o.key = key;
            o.references = references;
            o.remarks = remarks;
            o.severity = severity;
            o.summary = summary;
            o.targetId = targetId;
            o.title = title;
            return o;
        }
    }
}