// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstanceConnector;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance {
    /**
     * @return The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     * 
     */
    private String adrHomeDirectory;
    /**
     * @return The unique identifier of the Oracle cluster.
     * 
     */
    private String clusterId;
    /**
     * @return The connector details used to connect to the external DB system component.
     * 
     */
    private List<GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstanceConnector> connectors;
    /**
     * @return The Oracle base location of Cluster Ready Services (CRS).
     * 
     */
    private String crsBaseDirectory;
    /**
     * @return The host name of the database or the SCAN name in case of a RAC database.
     * 
     */
    private String hostName;
    /**
     * @return The role of the cluster node.
     * 
     */
    private String nodeRole;

    private GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance() {}
    /**
     * @return The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     * 
     */
    public String adrHomeDirectory() {
        return this.adrHomeDirectory;
    }
    /**
     * @return The unique identifier of the Oracle cluster.
     * 
     */
    public String clusterId() {
        return this.clusterId;
    }
    /**
     * @return The connector details used to connect to the external DB system component.
     * 
     */
    public List<GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstanceConnector> connectors() {
        return this.connectors;
    }
    /**
     * @return The Oracle base location of Cluster Ready Services (CRS).
     * 
     */
    public String crsBaseDirectory() {
        return this.crsBaseDirectory;
    }
    /**
     * @return The host name of the database or the SCAN name in case of a RAC database.
     * 
     */
    public String hostName() {
        return this.hostName;
    }
    /**
     * @return The role of the cluster node.
     * 
     */
    public String nodeRole() {
        return this.nodeRole;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adrHomeDirectory;
        private String clusterId;
        private List<GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstanceConnector> connectors;
        private String crsBaseDirectory;
        private String hostName;
        private String nodeRole;
        public Builder() {}
        public Builder(GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adrHomeDirectory = defaults.adrHomeDirectory;
    	      this.clusterId = defaults.clusterId;
    	      this.connectors = defaults.connectors;
    	      this.crsBaseDirectory = defaults.crsBaseDirectory;
    	      this.hostName = defaults.hostName;
    	      this.nodeRole = defaults.nodeRole;
        }

        @CustomType.Setter
        public Builder adrHomeDirectory(String adrHomeDirectory) {
            if (adrHomeDirectory == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance", "adrHomeDirectory");
            }
            this.adrHomeDirectory = adrHomeDirectory;
            return this;
        }
        @CustomType.Setter
        public Builder clusterId(String clusterId) {
            if (clusterId == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance", "clusterId");
            }
            this.clusterId = clusterId;
            return this;
        }
        @CustomType.Setter
        public Builder connectors(List<GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstanceConnector> connectors) {
            if (connectors == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance", "connectors");
            }
            this.connectors = connectors;
            return this;
        }
        public Builder connectors(GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstanceConnector... connectors) {
            return connectors(List.of(connectors));
        }
        @CustomType.Setter
        public Builder crsBaseDirectory(String crsBaseDirectory) {
            if (crsBaseDirectory == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance", "crsBaseDirectory");
            }
            this.crsBaseDirectory = crsBaseDirectory;
            return this;
        }
        @CustomType.Setter
        public Builder hostName(String hostName) {
            if (hostName == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance", "hostName");
            }
            this.hostName = hostName;
            return this;
        }
        @CustomType.Setter
        public Builder nodeRole(String nodeRole) {
            if (nodeRole == null) {
              throw new MissingRequiredPropertyException("GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance", "nodeRole");
            }
            this.nodeRole = nodeRole;
            return this;
        }
        public GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance build() {
            final var _resultValue = new GetExternalDbSystemDiscoveryDiscoveredComponentClusterInstance();
            _resultValue.adrHomeDirectory = adrHomeDirectory;
            _resultValue.clusterId = clusterId;
            _resultValue.connectors = connectors;
            _resultValue.crsBaseDirectory = crsBaseDirectory;
            _resultValue.hostName = hostName;
            _resultValue.nodeRole = nodeRole;
            return _resultValue;
        }
    }
}
