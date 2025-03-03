// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetCloudGuardConfigurationArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCloudGuardConfigurationArgs Empty = new GetCloudGuardConfigurationArgs();

    /**
     * The OCID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    private GetCloudGuardConfigurationArgs() {}

    private GetCloudGuardConfigurationArgs(GetCloudGuardConfigurationArgs $) {
        this.compartmentId = $.compartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCloudGuardConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCloudGuardConfigurationArgs $;

        public Builder() {
            $ = new GetCloudGuardConfigurationArgs();
        }

        public Builder(GetCloudGuardConfigurationArgs defaults) {
            $ = new GetCloudGuardConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public GetCloudGuardConfigurationArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetCloudGuardConfigurationArgs", "compartmentId");
            }
            return $;
        }
    }

}
