// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BdsInstanceClusterDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final BdsInstanceClusterDetailArgs Empty = new BdsInstanceClusterDetailArgs();

    /**
     * The URL of Ambari
     * 
     */
    @Import(name="ambariUrl")
    private @Nullable Output<String> ambariUrl;

    /**
     * @return The URL of Ambari
     * 
     */
    public Optional<Output<String>> ambariUrl() {
        return Optional.ofNullable(this.ambariUrl);
    }

    /**
     * Cloud SQL cell version
     * 
     */
    @Import(name="bdCellVersion")
    private @Nullable Output<String> bdCellVersion;

    /**
     * @return Cloud SQL cell version
     * 
     */
    public Optional<Output<String>> bdCellVersion() {
        return Optional.ofNullable(this.bdCellVersion);
    }

    /**
     * BDA version installed in the cluster
     * 
     */
    @Import(name="bdaVersion")
    private @Nullable Output<String> bdaVersion;

    /**
     * @return BDA version installed in the cluster
     * 
     */
    public Optional<Output<String>> bdaVersion() {
        return Optional.ofNullable(this.bdaVersion);
    }

    /**
     * Big Data Manager version installed in the cluster
     * 
     */
    @Import(name="bdmVersion")
    private @Nullable Output<String> bdmVersion;

    /**
     * @return Big Data Manager version installed in the cluster
     * 
     */
    public Optional<Output<String>> bdmVersion() {
        return Optional.ofNullable(this.bdmVersion);
    }

    /**
     * Big Data Service version installed in the cluster
     * 
     */
    @Import(name="bdsVersion")
    private @Nullable Output<String> bdsVersion;

    /**
     * @return Big Data Service version installed in the cluster
     * 
     */
    public Optional<Output<String>> bdsVersion() {
        return Optional.ofNullable(this.bdsVersion);
    }

    /**
     * The URL of a Big Data Manager
     * 
     */
    @Import(name="bigDataManagerUrl")
    private @Nullable Output<String> bigDataManagerUrl;

    /**
     * @return The URL of a Big Data Manager
     * 
     */
    public Optional<Output<String>> bigDataManagerUrl() {
        return Optional.ofNullable(this.bigDataManagerUrl);
    }

    /**
     * The URL of a Cloudera Manager
     * 
     */
    @Import(name="clouderaManagerUrl")
    private @Nullable Output<String> clouderaManagerUrl;

    /**
     * @return The URL of a Cloudera Manager
     * 
     */
    public Optional<Output<String>> clouderaManagerUrl() {
        return Optional.ofNullable(this.clouderaManagerUrl);
    }

    /**
     * Big Data SQL version
     * 
     */
    @Import(name="csqlCellVersion")
    private @Nullable Output<String> csqlCellVersion;

    /**
     * @return Big Data SQL version
     * 
     */
    public Optional<Output<String>> csqlCellVersion() {
        return Optional.ofNullable(this.csqlCellVersion);
    }

    /**
     * Query Server Database version
     * 
     */
    @Import(name="dbVersion")
    private @Nullable Output<String> dbVersion;

    /**
     * @return Query Server Database version
     * 
     */
    public Optional<Output<String>> dbVersion() {
        return Optional.ofNullable(this.dbVersion);
    }

    /**
     * The URL of a Hue Server
     * 
     */
    @Import(name="hueServerUrl")
    private @Nullable Output<String> hueServerUrl;

    /**
     * @return The URL of a Hue Server
     * 
     */
    public Optional<Output<String>> hueServerUrl() {
        return Optional.ofNullable(this.hueServerUrl);
    }

    /**
     * The URL of the Jupyterhub.
     * 
     */
    @Import(name="jupyterHubUrl")
    private @Nullable Output<String> jupyterHubUrl;

    /**
     * @return The URL of the Jupyterhub.
     * 
     */
    public Optional<Output<String>> jupyterHubUrl() {
        return Optional.ofNullable(this.jupyterHubUrl);
    }

    /**
     * Version of the ODH (Oracle Distribution including Apache Hadoop) installed on the cluster.
     * 
     */
    @Import(name="odhVersion")
    private @Nullable Output<String> odhVersion;

    /**
     * @return Version of the ODH (Oracle Distribution including Apache Hadoop) installed on the cluster.
     * 
     */
    public Optional<Output<String>> odhVersion() {
        return Optional.ofNullable(this.odhVersion);
    }

    /**
     * Oracle Linux version installed in the cluster
     * 
     */
    @Import(name="osVersion")
    private @Nullable Output<String> osVersion;

    /**
     * @return Oracle Linux version installed in the cluster
     * 
     */
    public Optional<Output<String>> osVersion() {
        return Optional.ofNullable(this.osVersion);
    }

    /**
     * The time the BDS instance was created. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the BDS instance was created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the BDS instance was automatically, or manually refreshed. An RFC3339 formatted datetime string
     * 
     */
    @Import(name="timeRefreshed")
    private @Nullable Output<String> timeRefreshed;

    /**
     * @return The time the BDS instance was automatically, or manually refreshed. An RFC3339 formatted datetime string
     * 
     */
    public Optional<Output<String>> timeRefreshed() {
        return Optional.ofNullable(this.timeRefreshed);
    }

    private BdsInstanceClusterDetailArgs() {}

    private BdsInstanceClusterDetailArgs(BdsInstanceClusterDetailArgs $) {
        this.ambariUrl = $.ambariUrl;
        this.bdCellVersion = $.bdCellVersion;
        this.bdaVersion = $.bdaVersion;
        this.bdmVersion = $.bdmVersion;
        this.bdsVersion = $.bdsVersion;
        this.bigDataManagerUrl = $.bigDataManagerUrl;
        this.clouderaManagerUrl = $.clouderaManagerUrl;
        this.csqlCellVersion = $.csqlCellVersion;
        this.dbVersion = $.dbVersion;
        this.hueServerUrl = $.hueServerUrl;
        this.jupyterHubUrl = $.jupyterHubUrl;
        this.odhVersion = $.odhVersion;
        this.osVersion = $.osVersion;
        this.timeCreated = $.timeCreated;
        this.timeRefreshed = $.timeRefreshed;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BdsInstanceClusterDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BdsInstanceClusterDetailArgs $;

        public Builder() {
            $ = new BdsInstanceClusterDetailArgs();
        }

        public Builder(BdsInstanceClusterDetailArgs defaults) {
            $ = new BdsInstanceClusterDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ambariUrl The URL of Ambari
         * 
         * @return builder
         * 
         */
        public Builder ambariUrl(@Nullable Output<String> ambariUrl) {
            $.ambariUrl = ambariUrl;
            return this;
        }

        /**
         * @param ambariUrl The URL of Ambari
         * 
         * @return builder
         * 
         */
        public Builder ambariUrl(String ambariUrl) {
            return ambariUrl(Output.of(ambariUrl));
        }

        /**
         * @param bdCellVersion Cloud SQL cell version
         * 
         * @return builder
         * 
         */
        public Builder bdCellVersion(@Nullable Output<String> bdCellVersion) {
            $.bdCellVersion = bdCellVersion;
            return this;
        }

        /**
         * @param bdCellVersion Cloud SQL cell version
         * 
         * @return builder
         * 
         */
        public Builder bdCellVersion(String bdCellVersion) {
            return bdCellVersion(Output.of(bdCellVersion));
        }

        /**
         * @param bdaVersion BDA version installed in the cluster
         * 
         * @return builder
         * 
         */
        public Builder bdaVersion(@Nullable Output<String> bdaVersion) {
            $.bdaVersion = bdaVersion;
            return this;
        }

        /**
         * @param bdaVersion BDA version installed in the cluster
         * 
         * @return builder
         * 
         */
        public Builder bdaVersion(String bdaVersion) {
            return bdaVersion(Output.of(bdaVersion));
        }

        /**
         * @param bdmVersion Big Data Manager version installed in the cluster
         * 
         * @return builder
         * 
         */
        public Builder bdmVersion(@Nullable Output<String> bdmVersion) {
            $.bdmVersion = bdmVersion;
            return this;
        }

        /**
         * @param bdmVersion Big Data Manager version installed in the cluster
         * 
         * @return builder
         * 
         */
        public Builder bdmVersion(String bdmVersion) {
            return bdmVersion(Output.of(bdmVersion));
        }

        /**
         * @param bdsVersion Big Data Service version installed in the cluster
         * 
         * @return builder
         * 
         */
        public Builder bdsVersion(@Nullable Output<String> bdsVersion) {
            $.bdsVersion = bdsVersion;
            return this;
        }

        /**
         * @param bdsVersion Big Data Service version installed in the cluster
         * 
         * @return builder
         * 
         */
        public Builder bdsVersion(String bdsVersion) {
            return bdsVersion(Output.of(bdsVersion));
        }

        /**
         * @param bigDataManagerUrl The URL of a Big Data Manager
         * 
         * @return builder
         * 
         */
        public Builder bigDataManagerUrl(@Nullable Output<String> bigDataManagerUrl) {
            $.bigDataManagerUrl = bigDataManagerUrl;
            return this;
        }

        /**
         * @param bigDataManagerUrl The URL of a Big Data Manager
         * 
         * @return builder
         * 
         */
        public Builder bigDataManagerUrl(String bigDataManagerUrl) {
            return bigDataManagerUrl(Output.of(bigDataManagerUrl));
        }

        /**
         * @param clouderaManagerUrl The URL of a Cloudera Manager
         * 
         * @return builder
         * 
         */
        public Builder clouderaManagerUrl(@Nullable Output<String> clouderaManagerUrl) {
            $.clouderaManagerUrl = clouderaManagerUrl;
            return this;
        }

        /**
         * @param clouderaManagerUrl The URL of a Cloudera Manager
         * 
         * @return builder
         * 
         */
        public Builder clouderaManagerUrl(String clouderaManagerUrl) {
            return clouderaManagerUrl(Output.of(clouderaManagerUrl));
        }

        /**
         * @param csqlCellVersion Big Data SQL version
         * 
         * @return builder
         * 
         */
        public Builder csqlCellVersion(@Nullable Output<String> csqlCellVersion) {
            $.csqlCellVersion = csqlCellVersion;
            return this;
        }

        /**
         * @param csqlCellVersion Big Data SQL version
         * 
         * @return builder
         * 
         */
        public Builder csqlCellVersion(String csqlCellVersion) {
            return csqlCellVersion(Output.of(csqlCellVersion));
        }

        /**
         * @param dbVersion Query Server Database version
         * 
         * @return builder
         * 
         */
        public Builder dbVersion(@Nullable Output<String> dbVersion) {
            $.dbVersion = dbVersion;
            return this;
        }

        /**
         * @param dbVersion Query Server Database version
         * 
         * @return builder
         * 
         */
        public Builder dbVersion(String dbVersion) {
            return dbVersion(Output.of(dbVersion));
        }

        /**
         * @param hueServerUrl The URL of a Hue Server
         * 
         * @return builder
         * 
         */
        public Builder hueServerUrl(@Nullable Output<String> hueServerUrl) {
            $.hueServerUrl = hueServerUrl;
            return this;
        }

        /**
         * @param hueServerUrl The URL of a Hue Server
         * 
         * @return builder
         * 
         */
        public Builder hueServerUrl(String hueServerUrl) {
            return hueServerUrl(Output.of(hueServerUrl));
        }

        /**
         * @param jupyterHubUrl The URL of the Jupyterhub.
         * 
         * @return builder
         * 
         */
        public Builder jupyterHubUrl(@Nullable Output<String> jupyterHubUrl) {
            $.jupyterHubUrl = jupyterHubUrl;
            return this;
        }

        /**
         * @param jupyterHubUrl The URL of the Jupyterhub.
         * 
         * @return builder
         * 
         */
        public Builder jupyterHubUrl(String jupyterHubUrl) {
            return jupyterHubUrl(Output.of(jupyterHubUrl));
        }

        /**
         * @param odhVersion Version of the ODH (Oracle Distribution including Apache Hadoop) installed on the cluster.
         * 
         * @return builder
         * 
         */
        public Builder odhVersion(@Nullable Output<String> odhVersion) {
            $.odhVersion = odhVersion;
            return this;
        }

        /**
         * @param odhVersion Version of the ODH (Oracle Distribution including Apache Hadoop) installed on the cluster.
         * 
         * @return builder
         * 
         */
        public Builder odhVersion(String odhVersion) {
            return odhVersion(Output.of(odhVersion));
        }

        /**
         * @param osVersion Oracle Linux version installed in the cluster
         * 
         * @return builder
         * 
         */
        public Builder osVersion(@Nullable Output<String> osVersion) {
            $.osVersion = osVersion;
            return this;
        }

        /**
         * @param osVersion Oracle Linux version installed in the cluster
         * 
         * @return builder
         * 
         */
        public Builder osVersion(String osVersion) {
            return osVersion(Output.of(osVersion));
        }

        /**
         * @param timeCreated The time the BDS instance was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the BDS instance was created. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeRefreshed The time the BDS instance was automatically, or manually refreshed. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeRefreshed(@Nullable Output<String> timeRefreshed) {
            $.timeRefreshed = timeRefreshed;
            return this;
        }

        /**
         * @param timeRefreshed The time the BDS instance was automatically, or manually refreshed. An RFC3339 formatted datetime string
         * 
         * @return builder
         * 
         */
        public Builder timeRefreshed(String timeRefreshed) {
            return timeRefreshed(Output.of(timeRefreshed));
        }

        public BdsInstanceClusterDetailArgs build() {
            return $;
        }
    }

}