// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetSecurityAssessmentArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSecurityAssessmentArgs Empty = new GetSecurityAssessmentArgs();

    /**
     * The OCID of the security assessment.
     * 
     */
    @Import(name="securityAssessmentId", required=true)
    private Output<String> securityAssessmentId;

    /**
     * @return The OCID of the security assessment.
     * 
     */
    public Output<String> securityAssessmentId() {
        return this.securityAssessmentId;
    }

    private GetSecurityAssessmentArgs() {}

    private GetSecurityAssessmentArgs(GetSecurityAssessmentArgs $) {
        this.securityAssessmentId = $.securityAssessmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSecurityAssessmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSecurityAssessmentArgs $;

        public Builder() {
            $ = new GetSecurityAssessmentArgs();
        }

        public Builder(GetSecurityAssessmentArgs defaults) {
            $ = new GetSecurityAssessmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param securityAssessmentId The OCID of the security assessment.
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
         * @return builder
         * 
         */
        public Builder securityAssessmentId(String securityAssessmentId) {
            return securityAssessmentId(Output.of(securityAssessmentId));
        }

        public GetSecurityAssessmentArgs build() {
            $.securityAssessmentId = Objects.requireNonNull($.securityAssessmentId, "expected parameter 'securityAssessmentId' to be non-null");
            return $;
        }
    }

}