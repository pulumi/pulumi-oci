// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNode {
    /**
     * @return Hostname for interface to the management node.
     * 
     */
    private String hostname;
    /**
     * @return Address of the management node.
     * 
     */
    private String ip;

    private GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNode() {}
    /**
     * @return Hostname for interface to the management node.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return Address of the management node.
     * 
     */
    public String ip() {
        return this.ip;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNode defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostname;
        private String ip;
        public Builder() {}
        public Builder(GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNode defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostname = defaults.hostname;
    	      this.ip = defaults.ip;
        }

        @CustomType.Setter
        public Builder hostname(String hostname) {
            if (hostname == null) {
              throw new MissingRequiredPropertyException("GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNode", "hostname");
            }
            this.hostname = hostname;
            return this;
        }
        @CustomType.Setter
        public Builder ip(String ip) {
            if (ip == null) {
              throw new MissingRequiredPropertyException("GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNode", "ip");
            }
            this.ip = ip;
            return this;
        }
        public GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNode build() {
            final var _resultValue = new GetAtCustomerCccInfrastructuresCccInfrastructureCollectionItemInfrastructureNetworkConfigurationManagementNode();
            _resultValue.hostname = hostname;
            _resultValue.ip = ip;
            return _resultValue;
        }
    }
}
