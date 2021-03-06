// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentFindingsFilter;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentFindingsFinding;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSecurityAssessmentFindingsResult {
    private final @Nullable String accessLevel;
    private final @Nullable Boolean compartmentIdInSubtree;
    private final @Nullable List<GetSecurityAssessmentFindingsFilter> filters;
    private final @Nullable String findingKey;
    /**
     * @return The list of findings.
     * 
     */
    private final List<GetSecurityAssessmentFindingsFinding> findings;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String securityAssessmentId;
    /**
     * @return The severity of the finding.
     * 
     */
    private final @Nullable String severity;

    @CustomType.Constructor
    private GetSecurityAssessmentFindingsResult(
        @CustomType.Parameter("accessLevel") @Nullable String accessLevel,
        @CustomType.Parameter("compartmentIdInSubtree") @Nullable Boolean compartmentIdInSubtree,
        @CustomType.Parameter("filters") @Nullable List<GetSecurityAssessmentFindingsFilter> filters,
        @CustomType.Parameter("findingKey") @Nullable String findingKey,
        @CustomType.Parameter("findings") List<GetSecurityAssessmentFindingsFinding> findings,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("securityAssessmentId") String securityAssessmentId,
        @CustomType.Parameter("severity") @Nullable String severity) {
        this.accessLevel = accessLevel;
        this.compartmentIdInSubtree = compartmentIdInSubtree;
        this.filters = filters;
        this.findingKey = findingKey;
        this.findings = findings;
        this.id = id;
        this.securityAssessmentId = securityAssessmentId;
        this.severity = severity;
    }

    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    public List<GetSecurityAssessmentFindingsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    public Optional<String> findingKey() {
        return Optional.ofNullable(this.findingKey);
    }
    /**
     * @return The list of findings.
     * 
     */
    public List<GetSecurityAssessmentFindingsFinding> findings() {
        return this.findings;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String securityAssessmentId() {
        return this.securityAssessmentId;
    }
    /**
     * @return The severity of the finding.
     * 
     */
    public Optional<String> severity() {
        return Optional.ofNullable(this.severity);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityAssessmentFindingsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String accessLevel;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable List<GetSecurityAssessmentFindingsFilter> filters;
        private @Nullable String findingKey;
        private List<GetSecurityAssessmentFindingsFinding> findings;
        private String id;
        private String securityAssessmentId;
        private @Nullable String severity;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSecurityAssessmentFindingsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.filters = defaults.filters;
    	      this.findingKey = defaults.findingKey;
    	      this.findings = defaults.findings;
    	      this.id = defaults.id;
    	      this.securityAssessmentId = defaults.securityAssessmentId;
    	      this.severity = defaults.severity;
        }

        public Builder accessLevel(@Nullable String accessLevel) {
            this.accessLevel = accessLevel;
            return this;
        }
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        public Builder filters(@Nullable List<GetSecurityAssessmentFindingsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSecurityAssessmentFindingsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder findingKey(@Nullable String findingKey) {
            this.findingKey = findingKey;
            return this;
        }
        public Builder findings(List<GetSecurityAssessmentFindingsFinding> findings) {
            this.findings = Objects.requireNonNull(findings);
            return this;
        }
        public Builder findings(GetSecurityAssessmentFindingsFinding... findings) {
            return findings(List.of(findings));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder securityAssessmentId(String securityAssessmentId) {
            this.securityAssessmentId = Objects.requireNonNull(securityAssessmentId);
            return this;
        }
        public Builder severity(@Nullable String severity) {
            this.severity = severity;
            return this;
        }        public GetSecurityAssessmentFindingsResult build() {
            return new GetSecurityAssessmentFindingsResult(accessLevel, compartmentIdInSubtree, filters, findingKey, findings, id, securityAssessmentId, severity);
        }
    }
}
