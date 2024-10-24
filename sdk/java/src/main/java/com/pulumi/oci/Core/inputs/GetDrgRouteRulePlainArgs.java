// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDrgRouteRulePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDrgRouteRulePlainArgs Empty = new GetDrgRouteRulePlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
     * 
     */
    @Import(name="drgRouteTableId", required=true)
    private String drgRouteTableId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
     * 
     */
    public String drgRouteTableId() {
        return this.drgRouteTableId;
    }

    private GetDrgRouteRulePlainArgs() {}

    private GetDrgRouteRulePlainArgs(GetDrgRouteRulePlainArgs $) {
        this.drgRouteTableId = $.drgRouteTableId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDrgRouteRulePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDrgRouteRulePlainArgs $;

        public Builder() {
            $ = new GetDrgRouteRulePlainArgs();
        }

        public Builder(GetDrgRouteRulePlainArgs defaults) {
            $ = new GetDrgRouteRulePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param drgRouteTableId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
         * 
         * @return builder
         * 
         */
        public Builder drgRouteTableId(String drgRouteTableId) {
            $.drgRouteTableId = drgRouteTableId;
            return this;
        }

        public GetDrgRouteRulePlainArgs build() {
            if ($.drgRouteTableId == null) {
                throw new MissingRequiredPropertyException("GetDrgRouteRulePlainArgs", "drgRouteTableId");
            }
            return $;
        }
    }

}
