// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetImportableComputeEntitiesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetImportableComputeEntitiesPlainArgs Empty = new GetImportableComputeEntitiesPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    private GetImportableComputeEntitiesPlainArgs() {}

    private GetImportableComputeEntitiesPlainArgs(GetImportableComputeEntitiesPlainArgs $) {
        this.compartmentId = $.compartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetImportableComputeEntitiesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetImportableComputeEntitiesPlainArgs $;

        public Builder() {
            $ = new GetImportableComputeEntitiesPlainArgs();
        }

        public Builder(GetImportableComputeEntitiesPlainArgs defaults) {
            $ = new GetImportableComputeEntitiesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public GetImportableComputeEntitiesPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}