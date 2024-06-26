// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetModelVersionSetArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetModelVersionSetArgs Empty = new GetModelVersionSetArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set.
     * 
     */
    @Import(name="modelVersionSetId", required=true)
    private Output<String> modelVersionSetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set.
     * 
     */
    public Output<String> modelVersionSetId() {
        return this.modelVersionSetId;
    }

    private GetModelVersionSetArgs() {}

    private GetModelVersionSetArgs(GetModelVersionSetArgs $) {
        this.modelVersionSetId = $.modelVersionSetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetModelVersionSetArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetModelVersionSetArgs $;

        public Builder() {
            $ = new GetModelVersionSetArgs();
        }

        public Builder(GetModelVersionSetArgs defaults) {
            $ = new GetModelVersionSetArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param modelVersionSetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetId(Output<String> modelVersionSetId) {
            $.modelVersionSetId = modelVersionSetId;
            return this;
        }

        /**
         * @param modelVersionSetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model version set.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetId(String modelVersionSetId) {
            return modelVersionSetId(Output.of(modelVersionSetId));
        }

        public GetModelVersionSetArgs build() {
            if ($.modelVersionSetId == null) {
                throw new MissingRequiredPropertyException("GetModelVersionSetArgs", "modelVersionSetId");
            }
            return $;
        }
    }

}
