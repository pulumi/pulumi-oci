// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SetSecurityAssessmentBaselineState extends com.pulumi.resources.ResourceArgs {

    public static final SetSecurityAssessmentBaselineState Empty = new SetSecurityAssessmentBaselineState();

    /**
     * List of security assessment OCIDs that need to be updated while setting the baseline.
     * 
     */
    @Import(name="assessmentIds")
    private @Nullable Output<List<String>> assessmentIds;

    /**
     * @return List of security assessment OCIDs that need to be updated while setting the baseline.
     * 
     */
    public Optional<Output<List<String>>> assessmentIds() {
        return Optional.ofNullable(this.assessmentIds);
    }

    /**
     * The OCID of the security assessment.
     * 
     */
    @Import(name="securityAssessmentId")
    private @Nullable Output<String> securityAssessmentId;

    /**
     * @return The OCID of the security assessment.
     * 
     */
    public Optional<Output<String>> securityAssessmentId() {
        return Optional.ofNullable(this.securityAssessmentId);
    }

    private SetSecurityAssessmentBaselineState() {}

    private SetSecurityAssessmentBaselineState(SetSecurityAssessmentBaselineState $) {
        this.assessmentIds = $.assessmentIds;
        this.securityAssessmentId = $.securityAssessmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SetSecurityAssessmentBaselineState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SetSecurityAssessmentBaselineState $;

        public Builder() {
            $ = new SetSecurityAssessmentBaselineState();
        }

        public Builder(SetSecurityAssessmentBaselineState defaults) {
            $ = new SetSecurityAssessmentBaselineState(Objects.requireNonNull(defaults));
        }

        /**
         * @param assessmentIds List of security assessment OCIDs that need to be updated while setting the baseline.
         * 
         * @return builder
         * 
         */
        public Builder assessmentIds(@Nullable Output<List<String>> assessmentIds) {
            $.assessmentIds = assessmentIds;
            return this;
        }

        /**
         * @param assessmentIds List of security assessment OCIDs that need to be updated while setting the baseline.
         * 
         * @return builder
         * 
         */
        public Builder assessmentIds(List<String> assessmentIds) {
            return assessmentIds(Output.of(assessmentIds));
        }

        /**
         * @param assessmentIds List of security assessment OCIDs that need to be updated while setting the baseline.
         * 
         * @return builder
         * 
         */
        public Builder assessmentIds(String... assessmentIds) {
            return assessmentIds(List.of(assessmentIds));
        }

        /**
         * @param securityAssessmentId The OCID of the security assessment.
         * 
         * @return builder
         * 
         */
        public Builder securityAssessmentId(@Nullable Output<String> securityAssessmentId) {
            $.securityAssessmentId = securityAssessmentId;
            return this;
        }

        /**
         * @param securityAssessmentId The OCID of the security assessment.
         * 
         * @return builder
         * 
         */
        public Builder securityAssessmentId(String securityAssessmentId) {
            return securityAssessmentId(Output.of(securityAssessmentId));
        }

        public SetSecurityAssessmentBaselineState build() {
            return $;
        }
    }

}