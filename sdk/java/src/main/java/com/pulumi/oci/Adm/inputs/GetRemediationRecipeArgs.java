// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Adm.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetRemediationRecipeArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRemediationRecipeArgs Empty = new GetRemediationRecipeArgs();

    /**
     * The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of a Remediation Recipe, as a URL path parameter.
     * 
     */
    @Import(name="remediationRecipeId", required=true)
    private Output<String> remediationRecipeId;

    /**
     * @return The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of a Remediation Recipe, as a URL path parameter.
     * 
     */
    public Output<String> remediationRecipeId() {
        return this.remediationRecipeId;
    }

    private GetRemediationRecipeArgs() {}

    private GetRemediationRecipeArgs(GetRemediationRecipeArgs $) {
        this.remediationRecipeId = $.remediationRecipeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRemediationRecipeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRemediationRecipeArgs $;

        public Builder() {
            $ = new GetRemediationRecipeArgs();
        }

        public Builder(GetRemediationRecipeArgs defaults) {
            $ = new GetRemediationRecipeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param remediationRecipeId The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of a Remediation Recipe, as a URL path parameter.
         * 
         * @return builder
         * 
         */
        public Builder remediationRecipeId(Output<String> remediationRecipeId) {
            $.remediationRecipeId = remediationRecipeId;
            return this;
        }

        /**
         * @param remediationRecipeId The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of a Remediation Recipe, as a URL path parameter.
         * 
         * @return builder
         * 
         */
        public Builder remediationRecipeId(String remediationRecipeId) {
            return remediationRecipeId(Output.of(remediationRecipeId));
        }

        public GetRemediationRecipeArgs build() {
            $.remediationRecipeId = Objects.requireNonNull($.remediationRecipeId, "expected parameter 'remediationRecipeId' to be non-null");
            return $;
        }
    }

}