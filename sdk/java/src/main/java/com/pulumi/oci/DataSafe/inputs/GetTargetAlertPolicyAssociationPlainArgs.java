// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetTargetAlertPolicyAssociationPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTargetAlertPolicyAssociationPlainArgs Empty = new GetTargetAlertPolicyAssociationPlainArgs();

    /**
     * The OCID of the target-alert policy association.
     * 
     */
    @Import(name="targetAlertPolicyAssociationId", required=true)
    private String targetAlertPolicyAssociationId;

    /**
     * @return The OCID of the target-alert policy association.
     * 
     */
    public String targetAlertPolicyAssociationId() {
        return this.targetAlertPolicyAssociationId;
    }

    private GetTargetAlertPolicyAssociationPlainArgs() {}

    private GetTargetAlertPolicyAssociationPlainArgs(GetTargetAlertPolicyAssociationPlainArgs $) {
        this.targetAlertPolicyAssociationId = $.targetAlertPolicyAssociationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTargetAlertPolicyAssociationPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTargetAlertPolicyAssociationPlainArgs $;

        public Builder() {
            $ = new GetTargetAlertPolicyAssociationPlainArgs();
        }

        public Builder(GetTargetAlertPolicyAssociationPlainArgs defaults) {
            $ = new GetTargetAlertPolicyAssociationPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param targetAlertPolicyAssociationId The OCID of the target-alert policy association.
         * 
         * @return builder
         * 
         */
        public Builder targetAlertPolicyAssociationId(String targetAlertPolicyAssociationId) {
            $.targetAlertPolicyAssociationId = targetAlertPolicyAssociationId;
            return this;
        }

        public GetTargetAlertPolicyAssociationPlainArgs build() {
            if ($.targetAlertPolicyAssociationId == null) {
                throw new MissingRequiredPropertyException("GetTargetAlertPolicyAssociationPlainArgs", "targetAlertPolicyAssociationId");
            }
            return $;
        }
    }

}
