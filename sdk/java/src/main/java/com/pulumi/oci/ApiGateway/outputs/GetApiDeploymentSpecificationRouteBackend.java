// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteBackendHeader;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteBackend {
    /**
     * @return The body of the stock response from the mock backend.
     * 
     */
    private String body;
    /**
     * @return Defines a timeout for establishing a connection with a proxied server.
     * 
     */
    private Double connectTimeoutInSeconds;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
     * 
     */
    private String functionId;
    private List<GetApiDeploymentSpecificationRouteBackendHeader> headers;
    /**
     * @return Defines whether or not to uphold SSL verification.
     * 
     */
    private Boolean isSslVerifyDisabled;
    /**
     * @return Defines a timeout for reading a response from the proxied server.
     * 
     */
    private Double readTimeoutInSeconds;
    /**
     * @return Defines a timeout for transmitting a request to the proxied server.
     * 
     */
    private Double sendTimeoutInSeconds;
    /**
     * @return The status code of the stock response from the mock backend.
     * 
     */
    private Integer status;
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    private String type;
    private String url;

    private GetApiDeploymentSpecificationRouteBackend() {}
    /**
     * @return The body of the stock response from the mock backend.
     * 
     */
    public String body() {
        return this.body;
    }
    /**
     * @return Defines a timeout for establishing a connection with a proxied server.
     * 
     */
    public Double connectTimeoutInSeconds() {
        return this.connectTimeoutInSeconds;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
     * 
     */
    public String functionId() {
        return this.functionId;
    }
    public List<GetApiDeploymentSpecificationRouteBackendHeader> headers() {
        return this.headers;
    }
    /**
     * @return Defines whether or not to uphold SSL verification.
     * 
     */
    public Boolean isSslVerifyDisabled() {
        return this.isSslVerifyDisabled;
    }
    /**
     * @return Defines a timeout for reading a response from the proxied server.
     * 
     */
    public Double readTimeoutInSeconds() {
        return this.readTimeoutInSeconds;
    }
    /**
     * @return Defines a timeout for transmitting a request to the proxied server.
     * 
     */
    public Double sendTimeoutInSeconds() {
        return this.sendTimeoutInSeconds;
    }
    /**
     * @return The status code of the stock response from the mock backend.
     * 
     */
    public Integer status() {
        return this.status;
    }
    /**
     * @return Type of the Response Cache Store Policy.
     * 
     */
    public String type() {
        return this.type;
    }
    public String url() {
        return this.url;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiDeploymentSpecificationRouteBackend defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String body;
        private Double connectTimeoutInSeconds;
        private String functionId;
        private List<GetApiDeploymentSpecificationRouteBackendHeader> headers;
        private Boolean isSslVerifyDisabled;
        private Double readTimeoutInSeconds;
        private Double sendTimeoutInSeconds;
        private Integer status;
        private String type;
        private String url;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteBackend defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.body = defaults.body;
    	      this.connectTimeoutInSeconds = defaults.connectTimeoutInSeconds;
    	      this.functionId = defaults.functionId;
    	      this.headers = defaults.headers;
    	      this.isSslVerifyDisabled = defaults.isSslVerifyDisabled;
    	      this.readTimeoutInSeconds = defaults.readTimeoutInSeconds;
    	      this.sendTimeoutInSeconds = defaults.sendTimeoutInSeconds;
    	      this.status = defaults.status;
    	      this.type = defaults.type;
    	      this.url = defaults.url;
        }

        @CustomType.Setter
        public Builder body(String body) {
            this.body = Objects.requireNonNull(body);
            return this;
        }
        @CustomType.Setter
        public Builder connectTimeoutInSeconds(Double connectTimeoutInSeconds) {
            this.connectTimeoutInSeconds = Objects.requireNonNull(connectTimeoutInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder functionId(String functionId) {
            this.functionId = Objects.requireNonNull(functionId);
            return this;
        }
        @CustomType.Setter
        public Builder headers(List<GetApiDeploymentSpecificationRouteBackendHeader> headers) {
            this.headers = Objects.requireNonNull(headers);
            return this;
        }
        public Builder headers(GetApiDeploymentSpecificationRouteBackendHeader... headers) {
            return headers(List.of(headers));
        }
        @CustomType.Setter
        public Builder isSslVerifyDisabled(Boolean isSslVerifyDisabled) {
            this.isSslVerifyDisabled = Objects.requireNonNull(isSslVerifyDisabled);
            return this;
        }
        @CustomType.Setter
        public Builder readTimeoutInSeconds(Double readTimeoutInSeconds) {
            this.readTimeoutInSeconds = Objects.requireNonNull(readTimeoutInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder sendTimeoutInSeconds(Double sendTimeoutInSeconds) {
            this.sendTimeoutInSeconds = Objects.requireNonNull(sendTimeoutInSeconds);
            return this;
        }
        @CustomType.Setter
        public Builder status(Integer status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder url(String url) {
            this.url = Objects.requireNonNull(url);
            return this;
        }
        public GetApiDeploymentSpecificationRouteBackend build() {
            final var o = new GetApiDeploymentSpecificationRouteBackend();
            o.body = body;
            o.connectTimeoutInSeconds = connectTimeoutInSeconds;
            o.functionId = functionId;
            o.headers = headers;
            o.isSslVerifyDisabled = isSslVerifyDisabled;
            o.readTimeoutInSeconds = readTimeoutInSeconds;
            o.sendTimeoutInSeconds = sendTimeoutInSeconds;
            o.status = status;
            o.type = type;
            o.url = url;
            return o;
        }
    }
}