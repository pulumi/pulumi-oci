// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetOdaPrivateEndpointArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOdaPrivateEndpointArgs Empty = new GetOdaPrivateEndpointArgs();

    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="odaPrivateEndpointId", required=true)
    private Output<String> odaPrivateEndpointId;

    /**
     * @return Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> odaPrivateEndpointId() {
        return this.odaPrivateEndpointId;
    }

    private GetOdaPrivateEndpointArgs() {}

    private GetOdaPrivateEndpointArgs(GetOdaPrivateEndpointArgs $) {
        this.odaPrivateEndpointId = $.odaPrivateEndpointId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOdaPrivateEndpointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOdaPrivateEndpointArgs $;

        public Builder() {
            $ = new GetOdaPrivateEndpointArgs();
        }

        public Builder(GetOdaPrivateEndpointArgs defaults) {
            $ = new GetOdaPrivateEndpointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param odaPrivateEndpointId Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointId(Output<String> odaPrivateEndpointId) {
            $.odaPrivateEndpointId = odaPrivateEndpointId;
            return this;
        }

        /**
         * @param odaPrivateEndpointId Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointId(String odaPrivateEndpointId) {
            return odaPrivateEndpointId(Output.of(odaPrivateEndpointId));
        }

        public GetOdaPrivateEndpointArgs build() {
            $.odaPrivateEndpointId = Objects.requireNonNull($.odaPrivateEndpointId, "expected parameter 'odaPrivateEndpointId' to be non-null");
            return $;
        }
    }

}