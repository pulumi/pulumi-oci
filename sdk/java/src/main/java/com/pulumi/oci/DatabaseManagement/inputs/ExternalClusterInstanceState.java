// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalClusterInstanceState extends com.pulumi.resources.ResourceArgs {

    public static final ExternalClusterInstanceState Empty = new ExternalClusterInstanceState();

    /**
     * The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     * 
     */
    @Import(name="adrHomeDirectory")
    private @Nullable Output<String> adrHomeDirectory;

    /**
     * @return The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     * 
     */
    public Optional<Output<String>> adrHomeDirectory() {
        return Optional.ofNullable(this.adrHomeDirectory);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The name of the external cluster instance.
     * 
     */
    @Import(name="componentName")
    private @Nullable Output<String> componentName;

    /**
     * @return The name of the external cluster instance.
     * 
     */
    public Optional<Output<String>> componentName() {
        return Optional.ofNullable(this.componentName);
    }

    /**
     * The Oracle base location of Cluster Ready Services (CRS).
     * 
     */
    @Import(name="crsBaseDirectory")
    private @Nullable Output<String> crsBaseDirectory;

    /**
     * @return The Oracle base location of Cluster Ready Services (CRS).
     * 
     */
    public Optional<Output<String>> crsBaseDirectory() {
        return Optional.ofNullable(this.crsBaseDirectory);
    }

    /**
     * The user-friendly name for the cluster instance. The name does not have to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The user-friendly name for the cluster instance. The name does not have to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
     * 
     */
    @Import(name="externalClusterId")
    private @Nullable Output<String> externalClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
     * 
     */
    public Optional<Output<String>> externalClusterId() {
        return Optional.ofNullable(this.externalClusterId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
     * 
     */
    @Import(name="externalClusterInstanceId")
    private @Nullable Output<String> externalClusterInstanceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
     * 
     */
    public Optional<Output<String>> externalClusterInstanceId() {
        return Optional.ofNullable(this.externalClusterInstanceId);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     * 
     */
    @Import(name="externalConnectorId")
    private @Nullable Output<String> externalConnectorId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
     * 
     */
    public Optional<Output<String>> externalConnectorId() {
        return Optional.ofNullable(this.externalConnectorId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
     * 
     */
    @Import(name="externalDbNodeId")
    private @Nullable Output<String> externalDbNodeId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
     * 
     */
    public Optional<Output<String>> externalDbNodeId() {
        return Optional.ofNullable(this.externalDbNodeId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster instance is a part of.
     * 
     */
    @Import(name="externalDbSystemId")
    private @Nullable Output<String> externalDbSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster instance is a part of.
     * 
     */
    public Optional<Output<String>> externalDbSystemId() {
        return Optional.ofNullable(this.externalDbSystemId);
    }

    /**
     * The name of the host on which the cluster instance is running.
     * 
     */
    @Import(name="hostName")
    private @Nullable Output<String> hostName;

    /**
     * @return The name of the host on which the cluster instance is running.
     * 
     */
    public Optional<Output<String>> hostName() {
        return Optional.ofNullable(this.hostName);
    }

    /**
     * Additional information about the current lifecycle state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The role of the cluster node.
     * 
     */
    @Import(name="nodeRole")
    private @Nullable Output<String> nodeRole;

    /**
     * @return The role of the cluster node.
     * 
     */
    public Optional<Output<String>> nodeRole() {
        return Optional.ofNullable(this.nodeRole);
    }

    /**
     * The current lifecycle state of the external cluster instance.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state of the external cluster instance.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the external cluster instance was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the external cluster instance was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the external cluster instance was last updated.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the external cluster instance was last updated.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private ExternalClusterInstanceState() {}

    private ExternalClusterInstanceState(ExternalClusterInstanceState $) {
        this.adrHomeDirectory = $.adrHomeDirectory;
        this.compartmentId = $.compartmentId;
        this.componentName = $.componentName;
        this.crsBaseDirectory = $.crsBaseDirectory;
        this.displayName = $.displayName;
        this.externalClusterId = $.externalClusterId;
        this.externalClusterInstanceId = $.externalClusterInstanceId;
        this.externalConnectorId = $.externalConnectorId;
        this.externalDbNodeId = $.externalDbNodeId;
        this.externalDbSystemId = $.externalDbSystemId;
        this.hostName = $.hostName;
        this.lifecycleDetails = $.lifecycleDetails;
        this.nodeRole = $.nodeRole;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalClusterInstanceState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalClusterInstanceState $;

        public Builder() {
            $ = new ExternalClusterInstanceState();
        }

        public Builder(ExternalClusterInstanceState defaults) {
            $ = new ExternalClusterInstanceState(Objects.requireNonNull(defaults));
        }

        /**
         * @param adrHomeDirectory The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder adrHomeDirectory(@Nullable Output<String> adrHomeDirectory) {
            $.adrHomeDirectory = adrHomeDirectory;
            return this;
        }

        /**
         * @param adrHomeDirectory The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder adrHomeDirectory(String adrHomeDirectory) {
            return adrHomeDirectory(Output.of(adrHomeDirectory));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param componentName The name of the external cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder componentName(@Nullable Output<String> componentName) {
            $.componentName = componentName;
            return this;
        }

        /**
         * @param componentName The name of the external cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder componentName(String componentName) {
            return componentName(Output.of(componentName));
        }

        /**
         * @param crsBaseDirectory The Oracle base location of Cluster Ready Services (CRS).
         * 
         * @return builder
         * 
         */
        public Builder crsBaseDirectory(@Nullable Output<String> crsBaseDirectory) {
            $.crsBaseDirectory = crsBaseDirectory;
            return this;
        }

        /**
         * @param crsBaseDirectory The Oracle base location of Cluster Ready Services (CRS).
         * 
         * @return builder
         * 
         */
        public Builder crsBaseDirectory(String crsBaseDirectory) {
            return crsBaseDirectory(Output.of(crsBaseDirectory));
        }

        /**
         * @param displayName The user-friendly name for the cluster instance. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The user-friendly name for the cluster instance. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param externalClusterId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
         * 
         * @return builder
         * 
         */
        public Builder externalClusterId(@Nullable Output<String> externalClusterId) {
            $.externalClusterId = externalClusterId;
            return this;
        }

        /**
         * @param externalClusterId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
         * 
         * @return builder
         * 
         */
        public Builder externalClusterId(String externalClusterId) {
            return externalClusterId(Output.of(externalClusterId));
        }

        /**
         * @param externalClusterInstanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder externalClusterInstanceId(@Nullable Output<String> externalClusterInstanceId) {
            $.externalClusterInstanceId = externalClusterInstanceId;
            return this;
        }

        /**
         * @param externalClusterInstanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder externalClusterInstanceId(String externalClusterInstanceId) {
            return externalClusterInstanceId(Output.of(externalClusterInstanceId));
        }

        /**
         * @param externalConnectorId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
         * 
         * @return builder
         * 
         */
        public Builder externalConnectorId(@Nullable Output<String> externalConnectorId) {
            $.externalConnectorId = externalConnectorId;
            return this;
        }

        /**
         * @param externalConnectorId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
         * 
         * @return builder
         * 
         */
        public Builder externalConnectorId(String externalConnectorId) {
            return externalConnectorId(Output.of(externalConnectorId));
        }

        /**
         * @param externalDbNodeId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
         * 
         * @return builder
         * 
         */
        public Builder externalDbNodeId(@Nullable Output<String> externalDbNodeId) {
            $.externalDbNodeId = externalDbNodeId;
            return this;
        }

        /**
         * @param externalDbNodeId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node.
         * 
         * @return builder
         * 
         */
        public Builder externalDbNodeId(String externalDbNodeId) {
            return externalDbNodeId(Output.of(externalDbNodeId));
        }

        /**
         * @param externalDbSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster instance is a part of.
         * 
         * @return builder
         * 
         */
        public Builder externalDbSystemId(@Nullable Output<String> externalDbSystemId) {
            $.externalDbSystemId = externalDbSystemId;
            return this;
        }

        /**
         * @param externalDbSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster instance is a part of.
         * 
         * @return builder
         * 
         */
        public Builder externalDbSystemId(String externalDbSystemId) {
            return externalDbSystemId(Output.of(externalDbSystemId));
        }

        /**
         * @param hostName The name of the host on which the cluster instance is running.
         * 
         * @return builder
         * 
         */
        public Builder hostName(@Nullable Output<String> hostName) {
            $.hostName = hostName;
            return this;
        }

        /**
         * @param hostName The name of the host on which the cluster instance is running.
         * 
         * @return builder
         * 
         */
        public Builder hostName(String hostName) {
            return hostName(Output.of(hostName));
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param nodeRole The role of the cluster node.
         * 
         * @return builder
         * 
         */
        public Builder nodeRole(@Nullable Output<String> nodeRole) {
            $.nodeRole = nodeRole;
            return this;
        }

        /**
         * @param nodeRole The role of the cluster node.
         * 
         * @return builder
         * 
         */
        public Builder nodeRole(String nodeRole) {
            return nodeRole(Output.of(nodeRole));
        }

        /**
         * @param state The current lifecycle state of the external cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state of the external cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the external cluster instance was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the external cluster instance was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the external cluster instance was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the external cluster instance was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public ExternalClusterInstanceState build() {
            return $;
        }
    }

}