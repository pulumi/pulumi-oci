// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waa.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetAppAccelerationPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAppAccelerationPlainArgs Empty = new GetAppAccelerationPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppAcceleration.
     * 
     */
    @Import(name="webAppAccelerationId", required=true)
    private String webAppAccelerationId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppAcceleration.
     * 
     */
    public String webAppAccelerationId() {
        return this.webAppAccelerationId;
    }

    private GetAppAccelerationPlainArgs() {}

    private GetAppAccelerationPlainArgs(GetAppAccelerationPlainArgs $) {
        this.webAppAccelerationId = $.webAppAccelerationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAppAccelerationPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAppAccelerationPlainArgs $;

        public Builder() {
            $ = new GetAppAccelerationPlainArgs();
        }

        public Builder(GetAppAccelerationPlainArgs defaults) {
            $ = new GetAppAccelerationPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param webAppAccelerationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppAcceleration.
         * 
         * @return builder
         * 
         */
        public Builder webAppAccelerationId(String webAppAccelerationId) {
            $.webAppAccelerationId = webAppAccelerationId;
            return this;
        }

        public GetAppAccelerationPlainArgs build() {
            $.webAppAccelerationId = Objects.requireNonNull($.webAppAccelerationId, "expected parameter 'webAppAccelerationId' to be non-null");
            return $;
        }
    }

}