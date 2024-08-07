// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteBackendHeader;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteBackendRoutingBackend;
import com.pulumi.oci.ApiGateway.outputs.GetApiDeploymentSpecificationRouteBackendSelectionSource;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiDeploymentSpecificationRouteBackend {
    private List<String> allowedPostLogoutUris;
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
     * @return Defines a state that should be shared on redirecting to postLogout URL.
     * 
     */
    private String postLogoutState;
    /**
     * @return Defines a timeout for reading a response from the proxied server.
     * 
     */
    private Double readTimeoutInSeconds;
    /**
     * @return List of backends to chose from for Dynamic Routing.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteBackendRoutingBackend> routingBackends;
    /**
     * @return Information around selector used for branching among routes/ authentication servers while dynamic routing/ authentication.
     * 
     */
    private List<GetApiDeploymentSpecificationRouteBackendSelectionSource> selectionSources;
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
    public List<String> allowedPostLogoutUris() {
        return this.allowedPostLogoutUris;
    }
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
     * @return Defines a state that should be shared on redirecting to postLogout URL.
     * 
     */
    public String postLogoutState() {
        return this.postLogoutState;
    }
    /**
     * @return Defines a timeout for reading a response from the proxied server.
     * 
     */
    public Double readTimeoutInSeconds() {
        return this.readTimeoutInSeconds;
    }
    /**
     * @return List of backends to chose from for Dynamic Routing.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteBackendRoutingBackend> routingBackends() {
        return this.routingBackends;
    }
    /**
     * @return Information around selector used for branching among routes/ authentication servers while dynamic routing/ authentication.
     * 
     */
    public List<GetApiDeploymentSpecificationRouteBackendSelectionSource> selectionSources() {
        return this.selectionSources;
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
        private List<String> allowedPostLogoutUris;
        private String body;
        private Double connectTimeoutInSeconds;
        private String functionId;
        private List<GetApiDeploymentSpecificationRouteBackendHeader> headers;
        private Boolean isSslVerifyDisabled;
        private String postLogoutState;
        private Double readTimeoutInSeconds;
        private List<GetApiDeploymentSpecificationRouteBackendRoutingBackend> routingBackends;
        private List<GetApiDeploymentSpecificationRouteBackendSelectionSource> selectionSources;
        private Double sendTimeoutInSeconds;
        private Integer status;
        private String type;
        private String url;
        public Builder() {}
        public Builder(GetApiDeploymentSpecificationRouteBackend defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowedPostLogoutUris = defaults.allowedPostLogoutUris;
    	      this.body = defaults.body;
    	      this.connectTimeoutInSeconds = defaults.connectTimeoutInSeconds;
    	      this.functionId = defaults.functionId;
    	      this.headers = defaults.headers;
    	      this.isSslVerifyDisabled = defaults.isSslVerifyDisabled;
    	      this.postLogoutState = defaults.postLogoutState;
    	      this.readTimeoutInSeconds = defaults.readTimeoutInSeconds;
    	      this.routingBackends = defaults.routingBackends;
    	      this.selectionSources = defaults.selectionSources;
    	      this.sendTimeoutInSeconds = defaults.sendTimeoutInSeconds;
    	      this.status = defaults.status;
    	      this.type = defaults.type;
    	      this.url = defaults.url;
        }

        @CustomType.Setter
        public Builder allowedPostLogoutUris(List<String> allowedPostLogoutUris) {
            if (allowedPostLogoutUris == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "allowedPostLogoutUris");
            }
            this.allowedPostLogoutUris = allowedPostLogoutUris;
            return this;
        }
        public Builder allowedPostLogoutUris(String... allowedPostLogoutUris) {
            return allowedPostLogoutUris(List.of(allowedPostLogoutUris));
        }
        @CustomType.Setter
        public Builder body(String body) {
            if (body == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "body");
            }
            this.body = body;
            return this;
        }
        @CustomType.Setter
        public Builder connectTimeoutInSeconds(Double connectTimeoutInSeconds) {
            if (connectTimeoutInSeconds == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "connectTimeoutInSeconds");
            }
            this.connectTimeoutInSeconds = connectTimeoutInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder functionId(String functionId) {
            if (functionId == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "functionId");
            }
            this.functionId = functionId;
            return this;
        }
        @CustomType.Setter
        public Builder headers(List<GetApiDeploymentSpecificationRouteBackendHeader> headers) {
            if (headers == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "headers");
            }
            this.headers = headers;
            return this;
        }
        public Builder headers(GetApiDeploymentSpecificationRouteBackendHeader... headers) {
            return headers(List.of(headers));
        }
        @CustomType.Setter
        public Builder isSslVerifyDisabled(Boolean isSslVerifyDisabled) {
            if (isSslVerifyDisabled == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "isSslVerifyDisabled");
            }
            this.isSslVerifyDisabled = isSslVerifyDisabled;
            return this;
        }
        @CustomType.Setter
        public Builder postLogoutState(String postLogoutState) {
            if (postLogoutState == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "postLogoutState");
            }
            this.postLogoutState = postLogoutState;
            return this;
        }
        @CustomType.Setter
        public Builder readTimeoutInSeconds(Double readTimeoutInSeconds) {
            if (readTimeoutInSeconds == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "readTimeoutInSeconds");
            }
            this.readTimeoutInSeconds = readTimeoutInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder routingBackends(List<GetApiDeploymentSpecificationRouteBackendRoutingBackend> routingBackends) {
            if (routingBackends == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "routingBackends");
            }
            this.routingBackends = routingBackends;
            return this;
        }
        public Builder routingBackends(GetApiDeploymentSpecificationRouteBackendRoutingBackend... routingBackends) {
            return routingBackends(List.of(routingBackends));
        }
        @CustomType.Setter
        public Builder selectionSources(List<GetApiDeploymentSpecificationRouteBackendSelectionSource> selectionSources) {
            if (selectionSources == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "selectionSources");
            }
            this.selectionSources = selectionSources;
            return this;
        }
        public Builder selectionSources(GetApiDeploymentSpecificationRouteBackendSelectionSource... selectionSources) {
            return selectionSources(List.of(selectionSources));
        }
        @CustomType.Setter
        public Builder sendTimeoutInSeconds(Double sendTimeoutInSeconds) {
            if (sendTimeoutInSeconds == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "sendTimeoutInSeconds");
            }
            this.sendTimeoutInSeconds = sendTimeoutInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder status(Integer status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder url(String url) {
            if (url == null) {
              throw new MissingRequiredPropertyException("GetApiDeploymentSpecificationRouteBackend", "url");
            }
            this.url = url;
            return this;
        }
        public GetApiDeploymentSpecificationRouteBackend build() {
            final var _resultValue = new GetApiDeploymentSpecificationRouteBackend();
            _resultValue.allowedPostLogoutUris = allowedPostLogoutUris;
            _resultValue.body = body;
            _resultValue.connectTimeoutInSeconds = connectTimeoutInSeconds;
            _resultValue.functionId = functionId;
            _resultValue.headers = headers;
            _resultValue.isSslVerifyDisabled = isSslVerifyDisabled;
            _resultValue.postLogoutState = postLogoutState;
            _resultValue.readTimeoutInSeconds = readTimeoutInSeconds;
            _resultValue.routingBackends = routingBackends;
            _resultValue.selectionSources = selectionSources;
            _resultValue.sendTimeoutInSeconds = sendTimeoutInSeconds;
            _resultValue.status = status;
            _resultValue.type = type;
            _resultValue.url = url;
            return _resultValue;
        }
    }
}
