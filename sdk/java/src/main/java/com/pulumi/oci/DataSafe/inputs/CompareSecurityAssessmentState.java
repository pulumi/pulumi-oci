// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CompareSecurityAssessmentState extends com.pulumi.resources.ResourceArgs {

    public static final CompareSecurityAssessmentState Empty = new CompareSecurityAssessmentState();

    /**
     * The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
     * 
     */
    @Import(name="comparisonSecurityAssessmentId")
    private @Nullable Output<String> comparisonSecurityAssessmentId;

    /**
     * @return The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
     * 
     */
    public Optional<Output<String>> comparisonSecurityAssessmentId() {
        return Optional.ofNullable(this.comparisonSecurityAssessmentId);
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

    private CompareSecurityAssessmentState() {}

    private CompareSecurityAssessmentState(CompareSecurityAssessmentState $) {
        this.comparisonSecurityAssessmentId = $.comparisonSecurityAssessmentId;
        this.securityAssessmentId = $.securityAssessmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CompareSecurityAssessmentState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CompareSecurityAssessmentState $;

        public Builder() {
            $ = new CompareSecurityAssessmentState();
        }

        public Builder(CompareSecurityAssessmentState defaults) {
            $ = new CompareSecurityAssessmentState(Objects.requireNonNull(defaults));
        }

        /**
         * @param comparisonSecurityAssessmentId The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
         * 
         * @return builder
         * 
         */
        public Builder comparisonSecurityAssessmentId(@Nullable Output<String> comparisonSecurityAssessmentId) {
            $.comparisonSecurityAssessmentId = comparisonSecurityAssessmentId;
            return this;
        }

        /**
         * @param comparisonSecurityAssessmentId The OCID of the security assessment. In this case a security assessment can be another security assessment, a latest assessment or a baseline.
         * 
         * @return builder
         * 
         */
        public Builder comparisonSecurityAssessmentId(String comparisonSecurityAssessmentId) {
            return comparisonSecurityAssessmentId(Output.of(comparisonSecurityAssessmentId));
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

        public CompareSecurityAssessmentState build() {
            return $;
        }
    }

}