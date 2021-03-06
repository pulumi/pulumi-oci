// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfigurationReverseConnectionsSourceIp;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfiguration {
    /**
     * @return A list of IP addresses in the customer VCN to be used as the source IPs for reverse connection packets traveling from the service&#39;s VCN to the customer&#39;s VCN.
     * 
     */
    private final List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfigurationReverseConnectionsSourceIp> reverseConnectionsSourceIps;

    @CustomType.Constructor
    private GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfiguration(@CustomType.Parameter("reverseConnectionsSourceIps") List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfigurationReverseConnectionsSourceIp> reverseConnectionsSourceIps) {
        this.reverseConnectionsSourceIps = reverseConnectionsSourceIps;
    }

    /**
     * @return A list of IP addresses in the customer VCN to be used as the source IPs for reverse connection packets traveling from the service&#39;s VCN to the customer&#39;s VCN.
     * 
     */
    public List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfigurationReverseConnectionsSourceIp> reverseConnectionsSourceIps() {
        return this.reverseConnectionsSourceIps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfiguration defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfigurationReverseConnectionsSourceIp> reverseConnectionsSourceIps;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.reverseConnectionsSourceIps = defaults.reverseConnectionsSourceIps;
        }

        public Builder reverseConnectionsSourceIps(List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfigurationReverseConnectionsSourceIp> reverseConnectionsSourceIps) {
            this.reverseConnectionsSourceIps = Objects.requireNonNull(reverseConnectionsSourceIps);
            return this;
        }
        public Builder reverseConnectionsSourceIps(GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfigurationReverseConnectionsSourceIp... reverseConnectionsSourceIps) {
            return reverseConnectionsSourceIps(List.of(reverseConnectionsSourceIps));
        }        public GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfiguration build() {
            return new GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollectionItemReverseConnectionConfiguration(reverseConnectionsSourceIps);
        }
    }
}
