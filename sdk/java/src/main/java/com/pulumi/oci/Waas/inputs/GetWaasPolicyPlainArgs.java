// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetWaasPolicyPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWaasPolicyPlainArgs Empty = new GetWaasPolicyPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     * 
     */
    @Import(name="waasPolicyId", required=true)
    private String waasPolicyId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     * 
     */
    public String waasPolicyId() {
        return this.waasPolicyId;
    }

    private GetWaasPolicyPlainArgs() {}

    private GetWaasPolicyPlainArgs(GetWaasPolicyPlainArgs $) {
        this.waasPolicyId = $.waasPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWaasPolicyPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWaasPolicyPlainArgs $;

        public Builder() {
            $ = new GetWaasPolicyPlainArgs();
        }

        public Builder(GetWaasPolicyPlainArgs defaults) {
            $ = new GetWaasPolicyPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param waasPolicyId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
         * 
         * @return builder
         * 
         */
        public Builder waasPolicyId(String waasPolicyId) {
            $.waasPolicyId = waasPolicyId;
            return this;
        }

        public GetWaasPolicyPlainArgs build() {
            $.waasPolicyId = Objects.requireNonNull($.waasPolicyId, "expected parameter 'waasPolicyId' to be non-null");
            return $;
        }
    }

}