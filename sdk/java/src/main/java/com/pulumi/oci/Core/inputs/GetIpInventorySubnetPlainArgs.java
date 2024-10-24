// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetIpInventorySubnetPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetIpInventorySubnetPlainArgs Empty = new GetIpInventorySubnetPlainArgs();

    /**
     * Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     * 
     */
    @Import(name="subnetId", required=true)
    private String subnetId;

    /**
     * @return Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }

    private GetIpInventorySubnetPlainArgs() {}

    private GetIpInventorySubnetPlainArgs(GetIpInventorySubnetPlainArgs $) {
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetIpInventorySubnetPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetIpInventorySubnetPlainArgs $;

        public Builder() {
            $ = new GetIpInventorySubnetPlainArgs();
        }

        public Builder(GetIpInventorySubnetPlainArgs defaults) {
            $ = new GetIpInventorySubnetPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param subnetId Specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        public GetIpInventorySubnetPlainArgs build() {
            if ($.subnetId == null) {
                throw new MissingRequiredPropertyException("GetIpInventorySubnetPlainArgs", "subnetId");
            }
            return $;
        }
    }

}
