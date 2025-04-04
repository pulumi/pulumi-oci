// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BdsInstanceClusterDetail {
    /**
     * @return The URL of Ambari
     * 
     */
    private @Nullable String ambariUrl;
    /**
     * @return Cloud SQL cell version.
     * 
     */
    private @Nullable String bdCellVersion;
    /**
     * @return BDA version installed in the cluster
     * 
     */
    private @Nullable String bdaVersion;
    /**
     * @return Big Data Manager version installed in the cluster.
     * 
     */
    private @Nullable String bdmVersion;
    /**
     * @return Big Data Service version installed in the cluster.
     * 
     */
    private @Nullable String bdsVersion;
    /**
     * @return The URL of Big Data Manager.
     * 
     */
    private @Nullable String bigDataManagerUrl;
    /**
     * @return The URL of Cloudera Manager
     * 
     */
    private @Nullable String clouderaManagerUrl;
    /**
     * @return Big Data SQL version.
     * 
     */
    private @Nullable String csqlCellVersion;
    /**
     * @return Cloud SQL query server database version.
     * 
     */
    private @Nullable String dbVersion;
    /**
     * @return The URL of the Hue server.
     * 
     */
    private @Nullable String hueServerUrl;
    /**
     * @return The URL of the Jupyterhub.
     * 
     */
    private @Nullable String jupyterHubUrl;
    /**
     * @return Version of the ODH (Oracle Distribution including Apache Hadoop) for the node.
     * 
     */
    private @Nullable String odhVersion;
    /**
     * @return BDS-assigned Operating System version for the node.
     * 
     */
    private @Nullable String osVersion;
    /**
     * @return The time the BDS instance was created. An RFC3339 formatted datetime string
     * 
     */
    private @Nullable String timeCreated;
    /**
     * @return The time the cluster was automatically or manually refreshed, shown as an RFC 3339 formatted datetime string.
     * 
     */
    private @Nullable String timeRefreshed;

    private BdsInstanceClusterDetail() {}
    /**
     * @return The URL of Ambari
     * 
     */
    public Optional<String> ambariUrl() {
        return Optional.ofNullable(this.ambariUrl);
    }
    /**
     * @return Cloud SQL cell version.
     * 
     */
    public Optional<String> bdCellVersion() {
        return Optional.ofNullable(this.bdCellVersion);
    }
    /**
     * @return BDA version installed in the cluster
     * 
     */
    public Optional<String> bdaVersion() {
        return Optional.ofNullable(this.bdaVersion);
    }
    /**
     * @return Big Data Manager version installed in the cluster.
     * 
     */
    public Optional<String> bdmVersion() {
        return Optional.ofNullable(this.bdmVersion);
    }
    /**
     * @return Big Data Service version installed in the cluster.
     * 
     */
    public Optional<String> bdsVersion() {
        return Optional.ofNullable(this.bdsVersion);
    }
    /**
     * @return The URL of Big Data Manager.
     * 
     */
    public Optional<String> bigDataManagerUrl() {
        return Optional.ofNullable(this.bigDataManagerUrl);
    }
    /**
     * @return The URL of Cloudera Manager
     * 
     */
    public Optional<String> clouderaManagerUrl() {
        return Optional.ofNullable(this.clouderaManagerUrl);
    }
    /**
     * @return Big Data SQL version.
     * 
     */
    public Optional<String> csqlCellVersion() {
        return Optional.ofNullable(this.csqlCellVersion);
    }
    /**
     * @return Cloud SQL query server database version.
     * 
     */
    public Optional<String> dbVersion() {
        return Optional.ofNullable(this.dbVersion);
    }
    /**
     * @return The URL of the Hue server.
     * 
     */
    public Optional<String> hueServerUrl() {
        return Optional.ofNullable(this.hueServerUrl);
    }
    /**
     * @return The URL of the Jupyterhub.
     * 
     */
    public Optional<String> jupyterHubUrl() {
        return Optional.ofNullable(this.jupyterHubUrl);
    }
    /**
     * @return Version of the ODH (Oracle Distribution including Apache Hadoop) for the node.
     * 
     */
    public Optional<String> odhVersion() {
        return Optional.ofNullable(this.odhVersion);
    }
    /**
     * @return BDS-assigned Operating System version for the node.
     * 
     */
    public Optional<String> osVersion() {
        return Optional.ofNullable(this.osVersion);
    }
    /**
     * @return The time the BDS instance was created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<String> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }
    /**
     * @return The time the cluster was automatically or manually refreshed, shown as an RFC 3339 formatted datetime string.
     * 
     */
    public Optional<String> timeRefreshed() {
        return Optional.ofNullable(this.timeRefreshed);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BdsInstanceClusterDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String ambariUrl;
        private @Nullable String bdCellVersion;
        private @Nullable String bdaVersion;
        private @Nullable String bdmVersion;
        private @Nullable String bdsVersion;
        private @Nullable String bigDataManagerUrl;
        private @Nullable String clouderaManagerUrl;
        private @Nullable String csqlCellVersion;
        private @Nullable String dbVersion;
        private @Nullable String hueServerUrl;
        private @Nullable String jupyterHubUrl;
        private @Nullable String odhVersion;
        private @Nullable String osVersion;
        private @Nullable String timeCreated;
        private @Nullable String timeRefreshed;
        public Builder() {}
        public Builder(BdsInstanceClusterDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ambariUrl = defaults.ambariUrl;
    	      this.bdCellVersion = defaults.bdCellVersion;
    	      this.bdaVersion = defaults.bdaVersion;
    	      this.bdmVersion = defaults.bdmVersion;
    	      this.bdsVersion = defaults.bdsVersion;
    	      this.bigDataManagerUrl = defaults.bigDataManagerUrl;
    	      this.clouderaManagerUrl = defaults.clouderaManagerUrl;
    	      this.csqlCellVersion = defaults.csqlCellVersion;
    	      this.dbVersion = defaults.dbVersion;
    	      this.hueServerUrl = defaults.hueServerUrl;
    	      this.jupyterHubUrl = defaults.jupyterHubUrl;
    	      this.odhVersion = defaults.odhVersion;
    	      this.osVersion = defaults.osVersion;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeRefreshed = defaults.timeRefreshed;
        }

        @CustomType.Setter
        public Builder ambariUrl(@Nullable String ambariUrl) {

            this.ambariUrl = ambariUrl;
            return this;
        }
        @CustomType.Setter
        public Builder bdCellVersion(@Nullable String bdCellVersion) {

            this.bdCellVersion = bdCellVersion;
            return this;
        }
        @CustomType.Setter
        public Builder bdaVersion(@Nullable String bdaVersion) {

            this.bdaVersion = bdaVersion;
            return this;
        }
        @CustomType.Setter
        public Builder bdmVersion(@Nullable String bdmVersion) {

            this.bdmVersion = bdmVersion;
            return this;
        }
        @CustomType.Setter
        public Builder bdsVersion(@Nullable String bdsVersion) {

            this.bdsVersion = bdsVersion;
            return this;
        }
        @CustomType.Setter
        public Builder bigDataManagerUrl(@Nullable String bigDataManagerUrl) {

            this.bigDataManagerUrl = bigDataManagerUrl;
            return this;
        }
        @CustomType.Setter
        public Builder clouderaManagerUrl(@Nullable String clouderaManagerUrl) {

            this.clouderaManagerUrl = clouderaManagerUrl;
            return this;
        }
        @CustomType.Setter
        public Builder csqlCellVersion(@Nullable String csqlCellVersion) {

            this.csqlCellVersion = csqlCellVersion;
            return this;
        }
        @CustomType.Setter
        public Builder dbVersion(@Nullable String dbVersion) {

            this.dbVersion = dbVersion;
            return this;
        }
        @CustomType.Setter
        public Builder hueServerUrl(@Nullable String hueServerUrl) {

            this.hueServerUrl = hueServerUrl;
            return this;
        }
        @CustomType.Setter
        public Builder jupyterHubUrl(@Nullable String jupyterHubUrl) {

            this.jupyterHubUrl = jupyterHubUrl;
            return this;
        }
        @CustomType.Setter
        public Builder odhVersion(@Nullable String odhVersion) {

            this.odhVersion = odhVersion;
            return this;
        }
        @CustomType.Setter
        public Builder osVersion(@Nullable String osVersion) {

            this.osVersion = osVersion;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(@Nullable String timeCreated) {

            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeRefreshed(@Nullable String timeRefreshed) {

            this.timeRefreshed = timeRefreshed;
            return this;
        }
        public BdsInstanceClusterDetail build() {
            final var _resultValue = new BdsInstanceClusterDetail();
            _resultValue.ambariUrl = ambariUrl;
            _resultValue.bdCellVersion = bdCellVersion;
            _resultValue.bdaVersion = bdaVersion;
            _resultValue.bdmVersion = bdmVersion;
            _resultValue.bdsVersion = bdsVersion;
            _resultValue.bigDataManagerUrl = bigDataManagerUrl;
            _resultValue.clouderaManagerUrl = clouderaManagerUrl;
            _resultValue.csqlCellVersion = csqlCellVersion;
            _resultValue.dbVersion = dbVersion;
            _resultValue.hueServerUrl = hueServerUrl;
            _resultValue.jupyterHubUrl = jupyterHubUrl;
            _resultValue.odhVersion = odhVersion;
            _resultValue.osVersion = osVersion;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeRefreshed = timeRefreshed;
            return _resultValue;
        }
    }
}
