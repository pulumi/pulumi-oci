// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentComparisonTargetPrivilegesAndRoleBaseline;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentComparisonTargetPrivilegesAndRoleCurrent;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityAssessmentComparisonTargetPrivilegesAndRole {
    /**
     * @return This array identifies the items that are present in the current assessment, but are missing from the baseline.
     * 
     */
    private final List<String> addedItems;
    /**
     * @return The particular finding reported by the security assessment.
     * 
     */
    private final List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleBaseline> baselines;
    /**
     * @return The particular finding reported by the security assessment.
     * 
     */
    private final List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleCurrent> currents;
    /**
     * @return This array contains the items that are present in both the current assessment and the baseline, but are different in the two assessments.
     * 
     */
    private final List<String> modifiedItems;
    /**
     * @return This array identifies the items that are present in the baseline, but are missing from the current assessment.
     * 
     */
    private final List<String> removedItems;
    /**
     * @return The severity of this diff.
     * 
     */
    private final String severity;

    @CustomType.Constructor
    private GetSecurityAssessmentComparisonTargetPrivilegesAndRole(
        @CustomType.Parameter("addedItems") List<String> addedItems,
        @CustomType.Parameter("baselines") List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleBaseline> baselines,
        @CustomType.Parameter("currents") List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleCurrent> currents,
        @CustomType.Parameter("modifiedItems") List<String> modifiedItems,
        @CustomType.Parameter("removedItems") List<String> removedItems,
        @CustomType.Parameter("severity") String severity) {
        this.addedItems = addedItems;
        this.baselines = baselines;
        this.currents = currents;
        this.modifiedItems = modifiedItems;
        this.removedItems = removedItems;
        this.severity = severity;
    }

    /**
     * @return This array identifies the items that are present in the current assessment, but are missing from the baseline.
     * 
     */
    public List<String> addedItems() {
        return this.addedItems;
    }
    /**
     * @return The particular finding reported by the security assessment.
     * 
     */
    public List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleBaseline> baselines() {
        return this.baselines;
    }
    /**
     * @return The particular finding reported by the security assessment.
     * 
     */
    public List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleCurrent> currents() {
        return this.currents;
    }
    /**
     * @return This array contains the items that are present in both the current assessment and the baseline, but are different in the two assessments.
     * 
     */
    public List<String> modifiedItems() {
        return this.modifiedItems;
    }
    /**
     * @return This array identifies the items that are present in the baseline, but are missing from the current assessment.
     * 
     */
    public List<String> removedItems() {
        return this.removedItems;
    }
    /**
     * @return The severity of this diff.
     * 
     */
    public String severity() {
        return this.severity;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityAssessmentComparisonTargetPrivilegesAndRole defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<String> addedItems;
        private List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleBaseline> baselines;
        private List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleCurrent> currents;
        private List<String> modifiedItems;
        private List<String> removedItems;
        private String severity;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSecurityAssessmentComparisonTargetPrivilegesAndRole defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.addedItems = defaults.addedItems;
    	      this.baselines = defaults.baselines;
    	      this.currents = defaults.currents;
    	      this.modifiedItems = defaults.modifiedItems;
    	      this.removedItems = defaults.removedItems;
    	      this.severity = defaults.severity;
        }

        public Builder addedItems(List<String> addedItems) {
            this.addedItems = Objects.requireNonNull(addedItems);
            return this;
        }
        public Builder addedItems(String... addedItems) {
            return addedItems(List.of(addedItems));
        }
        public Builder baselines(List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleBaseline> baselines) {
            this.baselines = Objects.requireNonNull(baselines);
            return this;
        }
        public Builder baselines(GetSecurityAssessmentComparisonTargetPrivilegesAndRoleBaseline... baselines) {
            return baselines(List.of(baselines));
        }
        public Builder currents(List<GetSecurityAssessmentComparisonTargetPrivilegesAndRoleCurrent> currents) {
            this.currents = Objects.requireNonNull(currents);
            return this;
        }
        public Builder currents(GetSecurityAssessmentComparisonTargetPrivilegesAndRoleCurrent... currents) {
            return currents(List.of(currents));
        }
        public Builder modifiedItems(List<String> modifiedItems) {
            this.modifiedItems = Objects.requireNonNull(modifiedItems);
            return this;
        }
        public Builder modifiedItems(String... modifiedItems) {
            return modifiedItems(List.of(modifiedItems));
        }
        public Builder removedItems(List<String> removedItems) {
            this.removedItems = Objects.requireNonNull(removedItems);
            return this;
        }
        public Builder removedItems(String... removedItems) {
            return removedItems(List.of(removedItems));
        }
        public Builder severity(String severity) {
            this.severity = Objects.requireNonNull(severity);
            return this;
        }        public GetSecurityAssessmentComparisonTargetPrivilegesAndRole build() {
            return new GetSecurityAssessmentComparisonTargetPrivilegesAndRole(addedItems, baselines, currents, modifiedItems, removedItems, severity);
        }
    }
}
