// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetConfigurationPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetConfigurationPlainArgs Empty = new GetConfigurationPlainArgs();

    /**
     * tenant id
     * 
     */
    @Import(name="tenantId", required=true)
    private String tenantId;

    /**
     * @return tenant id
     * 
     */
    public String tenantId() {
        return this.tenantId;
    }

    private GetConfigurationPlainArgs() {}

    private GetConfigurationPlainArgs(GetConfigurationPlainArgs $) {
        this.tenantId = $.tenantId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetConfigurationPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetConfigurationPlainArgs $;

        public Builder() {
            $ = new GetConfigurationPlainArgs();
        }

        public Builder(GetConfigurationPlainArgs defaults) {
            $ = new GetConfigurationPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param tenantId tenant id
         * 
         * @return builder
         * 
         */
        public Builder tenantId(String tenantId) {
            $.tenantId = tenantId;
            return this;
        }

        public GetConfigurationPlainArgs build() {
            $.tenantId = Objects.requireNonNull($.tenantId, "expected parameter 'tenantId' to be non-null");
            return $;
        }
    }

}