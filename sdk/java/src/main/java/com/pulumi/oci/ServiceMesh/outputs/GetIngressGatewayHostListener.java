// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewayHostListenerTl;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetIngressGatewayHostListener {
    /**
     * @return Port on which ingress gateway is listening.
     * 
     */
    private Integer port;
    /**
     * @return Type of protocol used.
     * 
     */
    private String protocol;
    /**
     * @return TLS enforcement config for the ingress listener.
     * 
     */
    private List<GetIngressGatewayHostListenerTl> tls;

    private GetIngressGatewayHostListener() {}
    /**
     * @return Port on which ingress gateway is listening.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return Type of protocol used.
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return TLS enforcement config for the ingress listener.
     * 
     */
    public List<GetIngressGatewayHostListenerTl> tls() {
        return this.tls;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIngressGatewayHostListener defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer port;
        private String protocol;
        private List<GetIngressGatewayHostListenerTl> tls;
        public Builder() {}
        public Builder(GetIngressGatewayHostListener defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.port = defaults.port;
    	      this.protocol = defaults.protocol;
    	      this.tls = defaults.tls;
        }

        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayHostListener", "port");
            }
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayHostListener", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder tls(List<GetIngressGatewayHostListenerTl> tls) {
            if (tls == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayHostListener", "tls");
            }
            this.tls = tls;
            return this;
        }
        public Builder tls(GetIngressGatewayHostListenerTl... tls) {
            return tls(List.of(tls));
        }
        public GetIngressGatewayHostListener build() {
            final var _resultValue = new GetIngressGatewayHostListener();
            _resultValue.port = port;
            _resultValue.protocol = protocol;
            _resultValue.tls = tls;
            return _resultValue;
        }
    }
}
