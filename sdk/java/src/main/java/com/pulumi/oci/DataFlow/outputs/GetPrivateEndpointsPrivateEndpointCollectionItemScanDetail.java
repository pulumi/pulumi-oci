// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPrivateEndpointsPrivateEndpointCollectionItemScanDetail {
    /**
     * @return A fully-qualified domain name (FQDN).
     * 
     */
    private String fqdn;
    /**
     * @return The port number of the FQDN
     * 
     */
    private String port;

    private GetPrivateEndpointsPrivateEndpointCollectionItemScanDetail() {}
    /**
     * @return A fully-qualified domain name (FQDN).
     * 
     */
    public String fqdn() {
        return this.fqdn;
    }
    /**
     * @return The port number of the FQDN
     * 
     */
    public String port() {
        return this.port;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPrivateEndpointsPrivateEndpointCollectionItemScanDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String fqdn;
        private String port;
        public Builder() {}
        public Builder(GetPrivateEndpointsPrivateEndpointCollectionItemScanDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.fqdn = defaults.fqdn;
    	      this.port = defaults.port;
        }

        @CustomType.Setter
        public Builder fqdn(String fqdn) {
            this.fqdn = Objects.requireNonNull(fqdn);
            return this;
        }
        @CustomType.Setter
        public Builder port(String port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }
        public GetPrivateEndpointsPrivateEndpointCollectionItemScanDetail build() {
            final var o = new GetPrivateEndpointsPrivateEndpointCollectionItemScanDetail();
            o.fqdn = fqdn;
            o.port = port;
            return o;
        }
    }
}