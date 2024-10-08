// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetDatabaseDatabaseDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final TargetDatabaseDatabaseDetailsArgs Empty = new TargetDatabaseDatabaseDetailsArgs();

    /**
     * (Updatable) The OCID of the Autonomous Database registered as a target database in Data Safe.
     * 
     */
    @Import(name="autonomousDatabaseId")
    private @Nullable Output<String> autonomousDatabaseId;

    /**
     * @return (Updatable) The OCID of the Autonomous Database registered as a target database in Data Safe.
     * 
     */
    public Optional<Output<String>> autonomousDatabaseId() {
        return Optional.ofNullable(this.autonomousDatabaseId);
    }

    /**
     * (Updatable) The database type.
     * 
     */
    @Import(name="databaseType", required=true)
    private Output<String> databaseType;

    /**
     * @return (Updatable) The database type.
     * 
     */
    public Output<String> databaseType() {
        return this.databaseType;
    }

    /**
     * (Updatable) The OCID of the cloud database registered as a target database in Data Safe.
     * 
     */
    @Import(name="dbSystemId")
    private @Nullable Output<String> dbSystemId;

    /**
     * @return (Updatable) The OCID of the cloud database registered as a target database in Data Safe.
     * 
     */
    public Optional<Output<String>> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }

    /**
     * (Updatable) The infrastructure type the database is running on.
     * 
     */
    @Import(name="infrastructureType", required=true)
    private Output<String> infrastructureType;

    /**
     * @return (Updatable) The infrastructure type the database is running on.
     * 
     */
    public Output<String> infrastructureType() {
        return this.infrastructureType;
    }

    /**
     * (Updatable) The OCID of the compute instance on which the database is running.
     * 
     */
    @Import(name="instanceId")
    private @Nullable Output<String> instanceId;

    /**
     * @return (Updatable) The OCID of the compute instance on which the database is running.
     * 
     */
    public Optional<Output<String>> instanceId() {
        return Optional.ofNullable(this.instanceId);
    }

    /**
     * (Updatable) The list of database host IP Addresses. Fully qualified domain names can be used if connectionType is &#39;ONPREM_CONNECTOR&#39;.
     * 
     */
    @Import(name="ipAddresses")
    private @Nullable Output<List<String>> ipAddresses;

    /**
     * @return (Updatable) The list of database host IP Addresses. Fully qualified domain names can be used if connectionType is &#39;ONPREM_CONNECTOR&#39;.
     * 
     */
    public Optional<Output<List<String>>> ipAddresses() {
        return Optional.ofNullable(this.ipAddresses);
    }

    /**
     * (Updatable) The port number of the database listener.
     * 
     */
    @Import(name="listenerPort")
    private @Nullable Output<Integer> listenerPort;

    /**
     * @return (Updatable) The port number of the database listener.
     * 
     */
    public Optional<Output<Integer>> listenerPort() {
        return Optional.ofNullable(this.listenerPort);
    }

    /**
     * (Updatable) The service name of the database registered as target database.
     * 
     */
    @Import(name="serviceName")
    private @Nullable Output<String> serviceName;

    /**
     * @return (Updatable) The service name of the database registered as target database.
     * 
     */
    public Optional<Output<String>> serviceName() {
        return Optional.ofNullable(this.serviceName);
    }

    /**
     * (Updatable) The OCID of the VM cluster in which the database is running.
     * 
     */
    @Import(name="vmClusterId")
    private @Nullable Output<String> vmClusterId;

    /**
     * @return (Updatable) The OCID of the VM cluster in which the database is running.
     * 
     */
    public Optional<Output<String>> vmClusterId() {
        return Optional.ofNullable(this.vmClusterId);
    }

    private TargetDatabaseDatabaseDetailsArgs() {}

    private TargetDatabaseDatabaseDetailsArgs(TargetDatabaseDatabaseDetailsArgs $) {
        this.autonomousDatabaseId = $.autonomousDatabaseId;
        this.databaseType = $.databaseType;
        this.dbSystemId = $.dbSystemId;
        this.infrastructureType = $.infrastructureType;
        this.instanceId = $.instanceId;
        this.ipAddresses = $.ipAddresses;
        this.listenerPort = $.listenerPort;
        this.serviceName = $.serviceName;
        this.vmClusterId = $.vmClusterId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetDatabaseDatabaseDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetDatabaseDatabaseDetailsArgs $;

        public Builder() {
            $ = new TargetDatabaseDatabaseDetailsArgs();
        }

        public Builder(TargetDatabaseDatabaseDetailsArgs defaults) {
            $ = new TargetDatabaseDatabaseDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousDatabaseId (Updatable) The OCID of the Autonomous Database registered as a target database in Data Safe.
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(@Nullable Output<String> autonomousDatabaseId) {
            $.autonomousDatabaseId = autonomousDatabaseId;
            return this;
        }

        /**
         * @param autonomousDatabaseId (Updatable) The OCID of the Autonomous Database registered as a target database in Data Safe.
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            return autonomousDatabaseId(Output.of(autonomousDatabaseId));
        }

        /**
         * @param databaseType (Updatable) The database type.
         * 
         * @return builder
         * 
         */
        public Builder databaseType(Output<String> databaseType) {
            $.databaseType = databaseType;
            return this;
        }

        /**
         * @param databaseType (Updatable) The database type.
         * 
         * @return builder
         * 
         */
        public Builder databaseType(String databaseType) {
            return databaseType(Output.of(databaseType));
        }

        /**
         * @param dbSystemId (Updatable) The OCID of the cloud database registered as a target database in Data Safe.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(@Nullable Output<String> dbSystemId) {
            $.dbSystemId = dbSystemId;
            return this;
        }

        /**
         * @param dbSystemId (Updatable) The OCID of the cloud database registered as a target database in Data Safe.
         * 
         * @return builder
         * 
         */
        public Builder dbSystemId(String dbSystemId) {
            return dbSystemId(Output.of(dbSystemId));
        }

        /**
         * @param infrastructureType (Updatable) The infrastructure type the database is running on.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureType(Output<String> infrastructureType) {
            $.infrastructureType = infrastructureType;
            return this;
        }

        /**
         * @param infrastructureType (Updatable) The infrastructure type the database is running on.
         * 
         * @return builder
         * 
         */
        public Builder infrastructureType(String infrastructureType) {
            return infrastructureType(Output.of(infrastructureType));
        }

        /**
         * @param instanceId (Updatable) The OCID of the compute instance on which the database is running.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(@Nullable Output<String> instanceId) {
            $.instanceId = instanceId;
            return this;
        }

        /**
         * @param instanceId (Updatable) The OCID of the compute instance on which the database is running.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(String instanceId) {
            return instanceId(Output.of(instanceId));
        }

        /**
         * @param ipAddresses (Updatable) The list of database host IP Addresses. Fully qualified domain names can be used if connectionType is &#39;ONPREM_CONNECTOR&#39;.
         * 
         * @return builder
         * 
         */
        public Builder ipAddresses(@Nullable Output<List<String>> ipAddresses) {
            $.ipAddresses = ipAddresses;
            return this;
        }

        /**
         * @param ipAddresses (Updatable) The list of database host IP Addresses. Fully qualified domain names can be used if connectionType is &#39;ONPREM_CONNECTOR&#39;.
         * 
         * @return builder
         * 
         */
        public Builder ipAddresses(List<String> ipAddresses) {
            return ipAddresses(Output.of(ipAddresses));
        }

        /**
         * @param ipAddresses (Updatable) The list of database host IP Addresses. Fully qualified domain names can be used if connectionType is &#39;ONPREM_CONNECTOR&#39;.
         * 
         * @return builder
         * 
         */
        public Builder ipAddresses(String... ipAddresses) {
            return ipAddresses(List.of(ipAddresses));
        }

        /**
         * @param listenerPort (Updatable) The port number of the database listener.
         * 
         * @return builder
         * 
         */
        public Builder listenerPort(@Nullable Output<Integer> listenerPort) {
            $.listenerPort = listenerPort;
            return this;
        }

        /**
         * @param listenerPort (Updatable) The port number of the database listener.
         * 
         * @return builder
         * 
         */
        public Builder listenerPort(Integer listenerPort) {
            return listenerPort(Output.of(listenerPort));
        }

        /**
         * @param serviceName (Updatable) The service name of the database registered as target database.
         * 
         * @return builder
         * 
         */
        public Builder serviceName(@Nullable Output<String> serviceName) {
            $.serviceName = serviceName;
            return this;
        }

        /**
         * @param serviceName (Updatable) The service name of the database registered as target database.
         * 
         * @return builder
         * 
         */
        public Builder serviceName(String serviceName) {
            return serviceName(Output.of(serviceName));
        }

        /**
         * @param vmClusterId (Updatable) The OCID of the VM cluster in which the database is running.
         * 
         * @return builder
         * 
         */
        public Builder vmClusterId(@Nullable Output<String> vmClusterId) {
            $.vmClusterId = vmClusterId;
            return this;
        }

        /**
         * @param vmClusterId (Updatable) The OCID of the VM cluster in which the database is running.
         * 
         * @return builder
         * 
         */
        public Builder vmClusterId(String vmClusterId) {
            return vmClusterId(Output.of(vmClusterId));
        }

        public TargetDatabaseDatabaseDetailsArgs build() {
            if ($.databaseType == null) {
                throw new MissingRequiredPropertyException("TargetDatabaseDatabaseDetailsArgs", "databaseType");
            }
            if ($.infrastructureType == null) {
                throw new MissingRequiredPropertyException("TargetDatabaseDatabaseDetailsArgs", "infrastructureType");
            }
            return $;
        }
    }

}
