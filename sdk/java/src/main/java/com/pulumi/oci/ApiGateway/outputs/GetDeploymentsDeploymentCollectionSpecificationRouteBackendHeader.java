// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionSpecificationRouteBackendHeader {
    /**
     * @return The case-insensitive name of the header.  This name must be unique across transformation policies.
     * 
     */
    private String name;
    /**
     * @return Value of the header.
     * 
     */
    private String value;

    private GetDeploymentsDeploymentCollectionSpecificationRouteBackendHeader() {}
    /**
     * @return The case-insensitive name of the header.  This name must be unique across transformation policies.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Value of the header.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionSpecificationRouteBackendHeader defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private String value;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionSpecificationRouteBackendHeader defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDeploymentsDeploymentCollectionSpecificationRouteBackendHeader build() {
            final var o = new GetDeploymentsDeploymentCollectionSpecificationRouteBackendHeader();
            o.name = name;
            o.value = value;
            return o;
        }
    }
}