// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentComparisonTargetDataEncryptionBaseline;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentComparisonTargetDataEncryptionCurrent;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityAssessmentComparisonTargetDataEncryption {
    /**
     * @return This array identifies the items that are present in the current assessment, but are missing from the baseline.
     * 
     */
    private List<String> addedItems;
    /**
     * @return The particular finding reported by the security assessment.
     * 
     */
    private List<GetSecurityAssessmentComparisonTargetDataEncryptionBaseline> baselines;
    /**
     * @return The particular finding reported by the security assessment.
     * 
     */
    private List<GetSecurityAssessmentComparisonTargetDataEncryptionCurrent> currents;
    /**
     * @return This array contains the items that are present in both the current assessment and the baseline, but are different in the two assessments.
     * 
     */
    private List<String> modifiedItems;
    /**
     * @return This array identifies the items that are present in the baseline, but are missing from the current assessment.
     * 
     */
    private List<String> removedItems;
    /**
     * @return The severity of this diff.
     * 
     */
    private String severity;

    private GetSecurityAssessmentComparisonTargetDataEncryption() {}
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
    public List<GetSecurityAssessmentComparisonTargetDataEncryptionBaseline> baselines() {
        return this.baselines;
    }
    /**
     * @return The particular finding reported by the security assessment.
     * 
     */
    public List<GetSecurityAssessmentComparisonTargetDataEncryptionCurrent> currents() {
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

    public static Builder builder(GetSecurityAssessmentComparisonTargetDataEncryption defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> addedItems;
        private List<GetSecurityAssessmentComparisonTargetDataEncryptionBaseline> baselines;
        private List<GetSecurityAssessmentComparisonTargetDataEncryptionCurrent> currents;
        private List<String> modifiedItems;
        private List<String> removedItems;
        private String severity;
        public Builder() {}
        public Builder(GetSecurityAssessmentComparisonTargetDataEncryption defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.addedItems = defaults.addedItems;
    	      this.baselines = defaults.baselines;
    	      this.currents = defaults.currents;
    	      this.modifiedItems = defaults.modifiedItems;
    	      this.removedItems = defaults.removedItems;
    	      this.severity = defaults.severity;
        }

        @CustomType.Setter
        public Builder addedItems(List<String> addedItems) {
            if (addedItems == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentComparisonTargetDataEncryption", "addedItems");
            }
            this.addedItems = addedItems;
            return this;
        }
        public Builder addedItems(String... addedItems) {
            return addedItems(List.of(addedItems));
        }
        @CustomType.Setter
        public Builder baselines(List<GetSecurityAssessmentComparisonTargetDataEncryptionBaseline> baselines) {
            if (baselines == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentComparisonTargetDataEncryption", "baselines");
            }
            this.baselines = baselines;
            return this;
        }
        public Builder baselines(GetSecurityAssessmentComparisonTargetDataEncryptionBaseline... baselines) {
            return baselines(List.of(baselines));
        }
        @CustomType.Setter
        public Builder currents(List<GetSecurityAssessmentComparisonTargetDataEncryptionCurrent> currents) {
            if (currents == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentComparisonTargetDataEncryption", "currents");
            }
            this.currents = currents;
            return this;
        }
        public Builder currents(GetSecurityAssessmentComparisonTargetDataEncryptionCurrent... currents) {
            return currents(List.of(currents));
        }
        @CustomType.Setter
        public Builder modifiedItems(List<String> modifiedItems) {
            if (modifiedItems == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentComparisonTargetDataEncryption", "modifiedItems");
            }
            this.modifiedItems = modifiedItems;
            return this;
        }
        public Builder modifiedItems(String... modifiedItems) {
            return modifiedItems(List.of(modifiedItems));
        }
        @CustomType.Setter
        public Builder removedItems(List<String> removedItems) {
            if (removedItems == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentComparisonTargetDataEncryption", "removedItems");
            }
            this.removedItems = removedItems;
            return this;
        }
        public Builder removedItems(String... removedItems) {
            return removedItems(List.of(removedItems));
        }
        @CustomType.Setter
        public Builder severity(String severity) {
            if (severity == null) {
              throw new MissingRequiredPropertyException("GetSecurityAssessmentComparisonTargetDataEncryption", "severity");
            }
            this.severity = severity;
            return this;
        }
        public GetSecurityAssessmentComparisonTargetDataEncryption build() {
            final var _resultValue = new GetSecurityAssessmentComparisonTargetDataEncryption();
            _resultValue.addedItems = addedItems;
            _resultValue.baselines = baselines;
            _resultValue.currents = currents;
            _resultValue.modifiedItems = modifiedItems;
            _resultValue.removedItems = removedItems;
            _resultValue.severity = severity;
            return _resultValue;
        }
    }
}
