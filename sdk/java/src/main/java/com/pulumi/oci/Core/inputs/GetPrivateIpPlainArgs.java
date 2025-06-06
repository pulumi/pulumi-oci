// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetPrivateIpPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPrivateIpPlainArgs Empty = new GetPrivateIpPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private IP or IPv6.
     * 
     */
    @Import(name="privateIpId", required=true)
    private String privateIpId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private IP or IPv6.
     * 
     */
    public String privateIpId() {
        return this.privateIpId;
    }

    private GetPrivateIpPlainArgs() {}

    private GetPrivateIpPlainArgs(GetPrivateIpPlainArgs $) {
        this.privateIpId = $.privateIpId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPrivateIpPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPrivateIpPlainArgs $;

        public Builder() {
            $ = new GetPrivateIpPlainArgs();
        }

        public Builder(GetPrivateIpPlainArgs defaults) {
            $ = new GetPrivateIpPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param privateIpId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private IP or IPv6.
         * 
         * @return builder
         * 
         */
        public Builder privateIpId(String privateIpId) {
            $.privateIpId = privateIpId;
            return this;
        }

        public GetPrivateIpPlainArgs build() {
            if ($.privateIpId == null) {
                throw new MissingRequiredPropertyException("GetPrivateIpPlainArgs", "privateIpId");
            }
            return $;
        }
    }

}
