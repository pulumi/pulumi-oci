// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDrgRouteRuleArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDrgRouteRuleArgs Empty = new GetDrgRouteRuleArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
     * 
     */
    @Import(name="drgRouteTableId", required=true)
    private Output<String> drgRouteTableId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
     * 
     */
    public Output<String> drgRouteTableId() {
        return this.drgRouteTableId;
    }

    private GetDrgRouteRuleArgs() {}

    private GetDrgRouteRuleArgs(GetDrgRouteRuleArgs $) {
        this.drgRouteTableId = $.drgRouteTableId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDrgRouteRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDrgRouteRuleArgs $;

        public Builder() {
            $ = new GetDrgRouteRuleArgs();
        }

        public Builder(GetDrgRouteRuleArgs defaults) {
            $ = new GetDrgRouteRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param drgRouteTableId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteTableId(Output<String> drgRouteTableId) {
            $.drgRouteTableId = drgRouteTableId;
            return this;
        }

        /**
         * @param drgRouteTableId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteTableId(String drgRouteTableId) {
            return drgRouteTableId(Output.of(drgRouteTableId));
        }

        public GetDrgRouteRuleArgs build() {
            if ($.drgRouteTableId == null) {
                throw new MissingRequiredPropertyException("GetDrgRouteRuleArgs", "drgRouteTableId");
            }
            return $;
        }
    }

}
