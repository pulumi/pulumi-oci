// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentComparisonTarget;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityAssessmentComparisonResult {
    /**
     * @return The OCID of the security assessment that is set as a baseline.
     * 
     */
    private final String baselineId;
    private final String comparisonSecurityAssessmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String securityAssessmentId;
    /**
     * @return The current state of the security assessment comparison.
     * 
     */
    private final String state;
    /**
     * @return A target-based comparison between two security assessments.
     * 
     */
    private final List<GetSecurityAssessmentComparisonTarget> targets;
    /**
     * @return The date and time when the security assessment comparison was created. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private final String timeCreated;

    @CustomType.Constructor
    private GetSecurityAssessmentComparisonResult(
        @CustomType.Parameter("baselineId") String baselineId,
        @CustomType.Parameter("comparisonSecurityAssessmentId") String comparisonSecurityAssessmentId,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("securityAssessmentId") String securityAssessmentId,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("targets") List<GetSecurityAssessmentComparisonTarget> targets,
        @CustomType.Parameter("timeCreated") String timeCreated) {
        this.baselineId = baselineId;
        this.comparisonSecurityAssessmentId = comparisonSecurityAssessmentId;
        this.id = id;
        this.securityAssessmentId = securityAssessmentId;
        this.state = state;
        this.targets = targets;
        this.timeCreated = timeCreated;
    }

    /**
     * @return The OCID of the security assessment that is set as a baseline.
     * 
     */
    public String baselineId() {
        return this.baselineId;
    }
    public String comparisonSecurityAssessmentId() {
        return this.comparisonSecurityAssessmentId;
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
     * @return The current state of the security assessment comparison.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return A target-based comparison between two security assessments.
     * 
     */
    public List<GetSecurityAssessmentComparisonTarget> targets() {
        return this.targets;
    }
    /**
     * @return The date and time when the security assessment comparison was created. Conforms to the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityAssessmentComparisonResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String baselineId;
        private String comparisonSecurityAssessmentId;
        private String id;
        private String securityAssessmentId;
        private String state;
        private List<GetSecurityAssessmentComparisonTarget> targets;
        private String timeCreated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSecurityAssessmentComparisonResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.baselineId = defaults.baselineId;
    	      this.comparisonSecurityAssessmentId = defaults.comparisonSecurityAssessmentId;
    	      this.id = defaults.id;
    	      this.securityAssessmentId = defaults.securityAssessmentId;
    	      this.state = defaults.state;
    	      this.targets = defaults.targets;
    	      this.timeCreated = defaults.timeCreated;
        }

        public Builder baselineId(String baselineId) {
            this.baselineId = Objects.requireNonNull(baselineId);
            return this;
        }
        public Builder comparisonSecurityAssessmentId(String comparisonSecurityAssessmentId) {
            this.comparisonSecurityAssessmentId = Objects.requireNonNull(comparisonSecurityAssessmentId);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder securityAssessmentId(String securityAssessmentId) {
            this.securityAssessmentId = Objects.requireNonNull(securityAssessmentId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder targets(List<GetSecurityAssessmentComparisonTarget> targets) {
            this.targets = Objects.requireNonNull(targets);
            return this;
        }
        public Builder targets(GetSecurityAssessmentComparisonTarget... targets) {
            return targets(List.of(targets));
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }        public GetSecurityAssessmentComparisonResult build() {
            return new GetSecurityAssessmentComparisonResult(baselineId, comparisonSecurityAssessmentId, id, securityAssessmentId, state, targets, timeCreated);
        }
    }
}
