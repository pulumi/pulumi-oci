// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetWebAppFirewallPolicyPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWebAppFirewallPolicyPlainArgs Empty = new GetWebAppFirewallPolicyPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewallPolicy.
     * 
     */
    @Import(name="webAppFirewallPolicyId", required=true)
    private String webAppFirewallPolicyId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewallPolicy.
     * 
     */
    public String webAppFirewallPolicyId() {
        return this.webAppFirewallPolicyId;
    }

    private GetWebAppFirewallPolicyPlainArgs() {}

    private GetWebAppFirewallPolicyPlainArgs(GetWebAppFirewallPolicyPlainArgs $) {
        this.webAppFirewallPolicyId = $.webAppFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWebAppFirewallPolicyPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWebAppFirewallPolicyPlainArgs $;

        public Builder() {
            $ = new GetWebAppFirewallPolicyPlainArgs();
        }

        public Builder(GetWebAppFirewallPolicyPlainArgs defaults) {
            $ = new GetWebAppFirewallPolicyPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param webAppFirewallPolicyId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewallPolicy.
         * 
         * @return builder
         * 
         */
        public Builder webAppFirewallPolicyId(String webAppFirewallPolicyId) {
            $.webAppFirewallPolicyId = webAppFirewallPolicyId;
            return this;
        }

        public GetWebAppFirewallPolicyPlainArgs build() {
            $.webAppFirewallPolicyId = Objects.requireNonNull($.webAppFirewallPolicyId, "expected parameter 'webAppFirewallPolicyId' to be non-null");
            return $;
        }
    }

}