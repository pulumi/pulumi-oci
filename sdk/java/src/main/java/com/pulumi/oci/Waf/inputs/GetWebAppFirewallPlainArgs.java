// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetWebAppFirewallPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWebAppFirewallPlainArgs Empty = new GetWebAppFirewallPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
     * 
     */
    @Import(name="webAppFirewallId", required=true)
    private String webAppFirewallId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
     * 
     */
    public String webAppFirewallId() {
        return this.webAppFirewallId;
    }

    private GetWebAppFirewallPlainArgs() {}

    private GetWebAppFirewallPlainArgs(GetWebAppFirewallPlainArgs $) {
        this.webAppFirewallId = $.webAppFirewallId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWebAppFirewallPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWebAppFirewallPlainArgs $;

        public Builder() {
            $ = new GetWebAppFirewallPlainArgs();
        }

        public Builder(GetWebAppFirewallPlainArgs defaults) {
            $ = new GetWebAppFirewallPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param webAppFirewallId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
         * 
         * @return builder
         * 
         */
        public Builder webAppFirewallId(String webAppFirewallId) {
            $.webAppFirewallId = webAppFirewallId;
            return this;
        }

        public GetWebAppFirewallPlainArgs build() {
            $.webAppFirewallId = Objects.requireNonNull($.webAppFirewallId, "expected parameter 'webAppFirewallId' to be non-null");
            return $;
        }
    }

}