// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.util.Objects;


public final class DomainsAuthenticationFactorSettingThirdPartyFactorArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsAuthenticationFactorSettingThirdPartyFactorArgs Empty = new DomainsAuthenticationFactorSettingThirdPartyFactorArgs();

    /**
     * (Updatable) To enable Duo Security factor
     * 
     */
    @Import(name="duoSecurity", required=true)
    private Output<Boolean> duoSecurity;

    /**
     * @return (Updatable) To enable Duo Security factor
     * 
     */
    public Output<Boolean> duoSecurity() {
        return this.duoSecurity;
    }

    private DomainsAuthenticationFactorSettingThirdPartyFactorArgs() {}

    private DomainsAuthenticationFactorSettingThirdPartyFactorArgs(DomainsAuthenticationFactorSettingThirdPartyFactorArgs $) {
        this.duoSecurity = $.duoSecurity;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsAuthenticationFactorSettingThirdPartyFactorArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsAuthenticationFactorSettingThirdPartyFactorArgs $;

        public Builder() {
            $ = new DomainsAuthenticationFactorSettingThirdPartyFactorArgs();
        }

        public Builder(DomainsAuthenticationFactorSettingThirdPartyFactorArgs defaults) {
            $ = new DomainsAuthenticationFactorSettingThirdPartyFactorArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param duoSecurity (Updatable) To enable Duo Security factor
         * 
         * @return builder
         * 
         */
        public Builder duoSecurity(Output<Boolean> duoSecurity) {
            $.duoSecurity = duoSecurity;
            return this;
        }

        /**
         * @param duoSecurity (Updatable) To enable Duo Security factor
         * 
         * @return builder
         * 
         */
        public Builder duoSecurity(Boolean duoSecurity) {
            return duoSecurity(Output.of(duoSecurity));
        }

        public DomainsAuthenticationFactorSettingThirdPartyFactorArgs build() {
            $.duoSecurity = Objects.requireNonNull($.duoSecurity, "expected parameter 'duoSecurity' to be non-null");
            return $;
        }
    }

}