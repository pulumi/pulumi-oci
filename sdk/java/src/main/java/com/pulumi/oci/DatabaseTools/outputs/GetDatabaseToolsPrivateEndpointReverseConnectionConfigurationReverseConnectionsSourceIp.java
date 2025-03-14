// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIp {
    /**
     * @return The IP address in the customer&#39;s VCN to be used as the source IP for reverse connection packets traveling from the customer&#39;s VCN to the service&#39;s VCN.
     * 
     */
    private String sourceIp;

    private GetDatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIp() {}
    /**
     * @return The IP address in the customer&#39;s VCN to be used as the source IP for reverse connection packets traveling from the customer&#39;s VCN to the service&#39;s VCN.
     * 
     */
    public String sourceIp() {
        return this.sourceIp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIp defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String sourceIp;
        public Builder() {}
        public Builder(GetDatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIp defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.sourceIp = defaults.sourceIp;
        }

        @CustomType.Setter
        public Builder sourceIp(String sourceIp) {
            if (sourceIp == null) {
              throw new MissingRequiredPropertyException("GetDatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIp", "sourceIp");
            }
            this.sourceIp = sourceIp;
            return this;
        }
        public GetDatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIp build() {
            final var _resultValue = new GetDatabaseToolsPrivateEndpointReverseConnectionConfigurationReverseConnectionsSourceIp();
            _resultValue.sourceIp = sourceIp;
            return _resultValue;
        }
    }
}
