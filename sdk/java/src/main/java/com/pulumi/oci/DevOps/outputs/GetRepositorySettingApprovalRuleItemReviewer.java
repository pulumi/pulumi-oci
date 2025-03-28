// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRepositorySettingApprovalRuleItemReviewer {
    /**
     * @return the OCID of the principal
     * 
     */
    private String principalId;
    /**
     * @return the name of the principal
     * 
     */
    private String principalName;
    /**
     * @return The state of the principal, it can be active or inactive or suppressed for emails
     * 
     */
    private String principalState;
    /**
     * @return the type of principal
     * 
     */
    private String principalType;

    private GetRepositorySettingApprovalRuleItemReviewer() {}
    /**
     * @return the OCID of the principal
     * 
     */
    public String principalId() {
        return this.principalId;
    }
    /**
     * @return the name of the principal
     * 
     */
    public String principalName() {
        return this.principalName;
    }
    /**
     * @return The state of the principal, it can be active or inactive or suppressed for emails
     * 
     */
    public String principalState() {
        return this.principalState;
    }
    /**
     * @return the type of principal
     * 
     */
    public String principalType() {
        return this.principalType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRepositorySettingApprovalRuleItemReviewer defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String principalId;
        private String principalName;
        private String principalState;
        private String principalType;
        public Builder() {}
        public Builder(GetRepositorySettingApprovalRuleItemReviewer defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.principalId = defaults.principalId;
    	      this.principalName = defaults.principalName;
    	      this.principalState = defaults.principalState;
    	      this.principalType = defaults.principalType;
        }

        @CustomType.Setter
        public Builder principalId(String principalId) {
            if (principalId == null) {
              throw new MissingRequiredPropertyException("GetRepositorySettingApprovalRuleItemReviewer", "principalId");
            }
            this.principalId = principalId;
            return this;
        }
        @CustomType.Setter
        public Builder principalName(String principalName) {
            if (principalName == null) {
              throw new MissingRequiredPropertyException("GetRepositorySettingApprovalRuleItemReviewer", "principalName");
            }
            this.principalName = principalName;
            return this;
        }
        @CustomType.Setter
        public Builder principalState(String principalState) {
            if (principalState == null) {
              throw new MissingRequiredPropertyException("GetRepositorySettingApprovalRuleItemReviewer", "principalState");
            }
            this.principalState = principalState;
            return this;
        }
        @CustomType.Setter
        public Builder principalType(String principalType) {
            if (principalType == null) {
              throw new MissingRequiredPropertyException("GetRepositorySettingApprovalRuleItemReviewer", "principalType");
            }
            this.principalType = principalType;
            return this;
        }
        public GetRepositorySettingApprovalRuleItemReviewer build() {
            final var _resultValue = new GetRepositorySettingApprovalRuleItemReviewer();
            _resultValue.principalId = principalId;
            _resultValue.principalName = principalName;
            _resultValue.principalState = principalState;
            _resultValue.principalType = principalType;
            return _resultValue;
        }
    }
}
