// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetSdmMaskingPolicyDifferencePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSdmMaskingPolicyDifferencePlainArgs Empty = new GetSdmMaskingPolicyDifferencePlainArgs();

    /**
     * The OCID of the SDM masking policy difference.
     * 
     */
    @Import(name="sdmMaskingPolicyDifferenceId", required=true)
    private String sdmMaskingPolicyDifferenceId;

    /**
     * @return The OCID of the SDM masking policy difference.
     * 
     */
    public String sdmMaskingPolicyDifferenceId() {
        return this.sdmMaskingPolicyDifferenceId;
    }

    private GetSdmMaskingPolicyDifferencePlainArgs() {}

    private GetSdmMaskingPolicyDifferencePlainArgs(GetSdmMaskingPolicyDifferencePlainArgs $) {
        this.sdmMaskingPolicyDifferenceId = $.sdmMaskingPolicyDifferenceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSdmMaskingPolicyDifferencePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSdmMaskingPolicyDifferencePlainArgs $;

        public Builder() {
            $ = new GetSdmMaskingPolicyDifferencePlainArgs();
        }

        public Builder(GetSdmMaskingPolicyDifferencePlainArgs defaults) {
            $ = new GetSdmMaskingPolicyDifferencePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param sdmMaskingPolicyDifferenceId The OCID of the SDM masking policy difference.
         * 
         * @return builder
         * 
         */
        public Builder sdmMaskingPolicyDifferenceId(String sdmMaskingPolicyDifferenceId) {
            $.sdmMaskingPolicyDifferenceId = sdmMaskingPolicyDifferenceId;
            return this;
        }

        public GetSdmMaskingPolicyDifferencePlainArgs build() {
            $.sdmMaskingPolicyDifferenceId = Objects.requireNonNull($.sdmMaskingPolicyDifferenceId, "expected parameter 'sdmMaskingPolicyDifferenceId' to be non-null");
            return $;
        }
    }

}