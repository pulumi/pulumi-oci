// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetModelDeploymentPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetModelDeploymentPlainArgs Empty = new GetModelDeploymentPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
     * 
     */
    @Import(name="modelDeploymentId", required=true)
    private String modelDeploymentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
     * 
     */
    public String modelDeploymentId() {
        return this.modelDeploymentId;
    }

    private GetModelDeploymentPlainArgs() {}

    private GetModelDeploymentPlainArgs(GetModelDeploymentPlainArgs $) {
        this.modelDeploymentId = $.modelDeploymentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetModelDeploymentPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetModelDeploymentPlainArgs $;

        public Builder() {
            $ = new GetModelDeploymentPlainArgs();
        }

        public Builder(GetModelDeploymentPlainArgs defaults) {
            $ = new GetModelDeploymentPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param modelDeploymentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
         * 
         * @return builder
         * 
         */
        public Builder modelDeploymentId(String modelDeploymentId) {
            $.modelDeploymentId = modelDeploymentId;
            return this;
        }

        public GetModelDeploymentPlainArgs build() {
            if ($.modelDeploymentId == null) {
                throw new MissingRequiredPropertyException("GetModelDeploymentPlainArgs", "modelDeploymentId");
            }
            return $;
        }
    }

}
