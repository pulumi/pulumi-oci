// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetOdaPrivateEndpointScanProxyArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOdaPrivateEndpointScanProxyArgs Empty = new GetOdaPrivateEndpointScanProxyArgs();

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

    /**
     * Unique ODA Private Endpoint Scan Proxy identifier.
     * 
     */
    @Import(name="odaPrivateEndpointScanProxyId", required=true)
    private Output<String> odaPrivateEndpointScanProxyId;

    /**
     * @return Unique ODA Private Endpoint Scan Proxy identifier.
     * 
     */
    public Output<String> odaPrivateEndpointScanProxyId() {
        return this.odaPrivateEndpointScanProxyId;
    }

    private GetOdaPrivateEndpointScanProxyArgs() {}

    private GetOdaPrivateEndpointScanProxyArgs(GetOdaPrivateEndpointScanProxyArgs $) {
        this.odaPrivateEndpointId = $.odaPrivateEndpointId;
        this.odaPrivateEndpointScanProxyId = $.odaPrivateEndpointScanProxyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOdaPrivateEndpointScanProxyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOdaPrivateEndpointScanProxyArgs $;

        public Builder() {
            $ = new GetOdaPrivateEndpointScanProxyArgs();
        }

        public Builder(GetOdaPrivateEndpointScanProxyArgs defaults) {
            $ = new GetOdaPrivateEndpointScanProxyArgs(Objects.requireNonNull(defaults));
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

        /**
         * @param odaPrivateEndpointScanProxyId Unique ODA Private Endpoint Scan Proxy identifier.
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointScanProxyId(Output<String> odaPrivateEndpointScanProxyId) {
            $.odaPrivateEndpointScanProxyId = odaPrivateEndpointScanProxyId;
            return this;
        }

        /**
         * @param odaPrivateEndpointScanProxyId Unique ODA Private Endpoint Scan Proxy identifier.
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointScanProxyId(String odaPrivateEndpointScanProxyId) {
            return odaPrivateEndpointScanProxyId(Output.of(odaPrivateEndpointScanProxyId));
        }

        public GetOdaPrivateEndpointScanProxyArgs build() {
            $.odaPrivateEndpointId = Objects.requireNonNull($.odaPrivateEndpointId, "expected parameter 'odaPrivateEndpointId' to be non-null");
            $.odaPrivateEndpointScanProxyId = Objects.requireNonNull($.odaPrivateEndpointScanProxyId, "expected parameter 'odaPrivateEndpointScanProxyId' to be non-null");
            return $;
        }
    }

}