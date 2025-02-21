// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetExternalExadataInfrastructureArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExternalExadataInfrastructureArgs Empty = new GetExternalExadataInfrastructureArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    @Import(name="externalExadataInfrastructureId", required=true)
    private Output<String> externalExadataInfrastructureId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    public Output<String> externalExadataInfrastructureId() {
        return this.externalExadataInfrastructureId;
    }

    private GetExternalExadataInfrastructureArgs() {}

    private GetExternalExadataInfrastructureArgs(GetExternalExadataInfrastructureArgs $) {
        this.externalExadataInfrastructureId = $.externalExadataInfrastructureId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExternalExadataInfrastructureArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExternalExadataInfrastructureArgs $;

        public Builder() {
            $ = new GetExternalExadataInfrastructureArgs();
        }

        public Builder(GetExternalExadataInfrastructureArgs defaults) {
            $ = new GetExternalExadataInfrastructureArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param externalExadataInfrastructureId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder externalExadataInfrastructureId(Output<String> externalExadataInfrastructureId) {
            $.externalExadataInfrastructureId = externalExadataInfrastructureId;
            return this;
        }

        /**
         * @param externalExadataInfrastructureId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder externalExadataInfrastructureId(String externalExadataInfrastructureId) {
            return externalExadataInfrastructureId(Output.of(externalExadataInfrastructureId));
        }

        public GetExternalExadataInfrastructureArgs build() {
            if ($.externalExadataInfrastructureId == null) {
                throw new MissingRequiredPropertyException("GetExternalExadataInfrastructureArgs", "externalExadataInfrastructureId");
            }
            return $;
        }
    }

}
