// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SetSecurityAssessmentBaselineArgs extends com.pulumi.resources.ResourceArgs {

    public static final SetSecurityAssessmentBaselineArgs Empty = new SetSecurityAssessmentBaselineArgs();

    /**
     * The list of OCIDs for the security assessments that need to be updated while setting the baseline.
     * 
     */
    @Import(name="assessmentIds")
    private @Nullable Output<List<String>> assessmentIds;

    /**
     * @return The list of OCIDs for the security assessments that need to be updated while setting the baseline.
     * 
     */
    public Optional<Output<List<String>>> assessmentIds() {
        return Optional.ofNullable(this.assessmentIds);
    }

    /**
     * The OCID of the security assessment.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="securityAssessmentId", required=true)
    private Output<String> securityAssessmentId;

    /**
     * @return The OCID of the security assessment.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> securityAssessmentId() {
        return this.securityAssessmentId;
    }

    private SetSecurityAssessmentBaselineArgs() {}

    private SetSecurityAssessmentBaselineArgs(SetSecurityAssessmentBaselineArgs $) {
        this.assessmentIds = $.assessmentIds;
        this.securityAssessmentId = $.securityAssessmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SetSecurityAssessmentBaselineArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SetSecurityAssessmentBaselineArgs $;

        public Builder() {
            $ = new SetSecurityAssessmentBaselineArgs();
        }

        public Builder(SetSecurityAssessmentBaselineArgs defaults) {
            $ = new SetSecurityAssessmentBaselineArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param assessmentIds The list of OCIDs for the security assessments that need to be updated while setting the baseline.
         * 
         * @return builder
         * 
         */
        public Builder assessmentIds(@Nullable Output<List<String>> assessmentIds) {
            $.assessmentIds = assessmentIds;
            return this;
        }

        /**
         * @param assessmentIds The list of OCIDs for the security assessments that need to be updated while setting the baseline.
         * 
         * @return builder
         * 
         */
        public Builder assessmentIds(List<String> assessmentIds) {
            return assessmentIds(Output.of(assessmentIds));
        }

        /**
         * @param assessmentIds The list of OCIDs for the security assessments that need to be updated while setting the baseline.
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
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder securityAssessmentId(Output<String> securityAssessmentId) {
            $.securityAssessmentId = securityAssessmentId;
            return this;
        }

        /**
         * @param securityAssessmentId The OCID of the security assessment.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder securityAssessmentId(String securityAssessmentId) {
            return securityAssessmentId(Output.of(securityAssessmentId));
        }

        public SetSecurityAssessmentBaselineArgs build() {
            if ($.securityAssessmentId == null) {
                throw new MissingRequiredPropertyException("SetSecurityAssessmentBaselineArgs", "securityAssessmentId");
            }
            return $;
        }
    }

}
