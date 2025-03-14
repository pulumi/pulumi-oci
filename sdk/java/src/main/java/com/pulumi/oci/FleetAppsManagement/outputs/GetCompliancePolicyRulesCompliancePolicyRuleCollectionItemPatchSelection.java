// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection {
    /**
     * @return Days passed since patch release.
     * 
     */
    private Integer daysSinceRelease;
    /**
     * @return Patch Name.
     * 
     */
    private String patchLevel;
    /**
     * @return A filter to return only resources that match the patch selection against the given patch name.
     * 
     */
    private String patchName;
    /**
     * @return Selection type for the Patch.
     * 
     */
    private String selectionType;

    private GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection() {}
    /**
     * @return Days passed since patch release.
     * 
     */
    public Integer daysSinceRelease() {
        return this.daysSinceRelease;
    }
    /**
     * @return Patch Name.
     * 
     */
    public String patchLevel() {
        return this.patchLevel;
    }
    /**
     * @return A filter to return only resources that match the patch selection against the given patch name.
     * 
     */
    public String patchName() {
        return this.patchName;
    }
    /**
     * @return Selection type for the Patch.
     * 
     */
    public String selectionType() {
        return this.selectionType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer daysSinceRelease;
        private String patchLevel;
        private String patchName;
        private String selectionType;
        public Builder() {}
        public Builder(GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.daysSinceRelease = defaults.daysSinceRelease;
    	      this.patchLevel = defaults.patchLevel;
    	      this.patchName = defaults.patchName;
    	      this.selectionType = defaults.selectionType;
        }

        @CustomType.Setter
        public Builder daysSinceRelease(Integer daysSinceRelease) {
            if (daysSinceRelease == null) {
              throw new MissingRequiredPropertyException("GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection", "daysSinceRelease");
            }
            this.daysSinceRelease = daysSinceRelease;
            return this;
        }
        @CustomType.Setter
        public Builder patchLevel(String patchLevel) {
            if (patchLevel == null) {
              throw new MissingRequiredPropertyException("GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection", "patchLevel");
            }
            this.patchLevel = patchLevel;
            return this;
        }
        @CustomType.Setter
        public Builder patchName(String patchName) {
            if (patchName == null) {
              throw new MissingRequiredPropertyException("GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection", "patchName");
            }
            this.patchName = patchName;
            return this;
        }
        @CustomType.Setter
        public Builder selectionType(String selectionType) {
            if (selectionType == null) {
              throw new MissingRequiredPropertyException("GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection", "selectionType");
            }
            this.selectionType = selectionType;
            return this;
        }
        public GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection build() {
            final var _resultValue = new GetCompliancePolicyRulesCompliancePolicyRuleCollectionItemPatchSelection();
            _resultValue.daysSinceRelease = daysSinceRelease;
            _resultValue.patchLevel = patchLevel;
            _resultValue.patchName = patchName;
            _resultValue.selectionType = selectionType;
            return _resultValue;
        }
    }
}
