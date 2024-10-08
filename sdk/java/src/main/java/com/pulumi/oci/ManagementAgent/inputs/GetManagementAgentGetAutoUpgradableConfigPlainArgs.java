// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetManagementAgentGetAutoUpgradableConfigPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagementAgentGetAutoUpgradableConfigPlainArgs Empty = new GetManagementAgentGetAutoUpgradableConfigPlainArgs();

    /**
     * The OCID of the compartment to which a request will be scoped.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the compartment to which a request will be scoped.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    private GetManagementAgentGetAutoUpgradableConfigPlainArgs() {}

    private GetManagementAgentGetAutoUpgradableConfigPlainArgs(GetManagementAgentGetAutoUpgradableConfigPlainArgs $) {
        this.compartmentId = $.compartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagementAgentGetAutoUpgradableConfigPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagementAgentGetAutoUpgradableConfigPlainArgs $;

        public Builder() {
            $ = new GetManagementAgentGetAutoUpgradableConfigPlainArgs();
        }

        public Builder(GetManagementAgentGetAutoUpgradableConfigPlainArgs defaults) {
            $ = new GetManagementAgentGetAutoUpgradableConfigPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment to which a request will be scoped.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public GetManagementAgentGetAutoUpgradableConfigPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetManagementAgentGetAutoUpgradableConfigPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
