// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalDbSystemConnectorConnectionInfoArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalDbSystemConnectorState extends com.pulumi.resources.ResourceArgs {

    public static final ExternalDbSystemConnectorState Empty = new ExternalDbSystemConnectorState();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
     * 
     */
    @Import(name="agentId")
    private @Nullable Output<String> agentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
     * 
     */
    public Optional<Output<String>> agentId() {
        return Optional.ofNullable(this.agentId);
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
     * The error message indicating the reason for connection failure or `null` if the connection was successful.
     * 
     */
    @Import(name="connectionFailureMessage")
    private @Nullable Output<String> connectionFailureMessage;

    /**
     * @return The error message indicating the reason for connection failure or `null` if the connection was successful.
     * 
     */
    public Optional<Output<String>> connectionFailureMessage() {
        return Optional.ofNullable(this.connectionFailureMessage);
    }

    /**
     * The connection details required to connect to an external DB system component.
     * 
     */
    @Import(name="connectionInfos")
    private @Nullable Output<List<ExternalDbSystemConnectorConnectionInfoArgs>> connectionInfos;

    /**
     * @return The connection details required to connect to an external DB system component.
     * 
     */
    public Optional<Output<List<ExternalDbSystemConnectorConnectionInfoArgs>>> connectionInfos() {
        return Optional.ofNullable(this.connectionInfos);
    }

    /**
     * The status of connectivity to the external DB system component.
     * 
     */
    @Import(name="connectionStatus")
    private @Nullable Output<String> connectionStatus;

    /**
     * @return The status of connectivity to the external DB system component.
     * 
     */
    public Optional<Output<String>> connectionStatus() {
        return Optional.ofNullable(this.connectionStatus);
    }

    /**
     * (Updatable) The type of connector.
     * 
     */
    @Import(name="connectorType")
    private @Nullable Output<String> connectorType;

    /**
     * @return (Updatable) The type of connector.
     * 
     */
    public Optional<Output<String>> connectorType() {
        return Optional.ofNullable(this.connectorType);
    }

    /**
     * The user-friendly name for the external connector. The name does not have to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return The user-friendly name for the external connector. The name does not have to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     * 
     */
    @Import(name="externalDbSystemId")
    private @Nullable Output<String> externalDbSystemId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     * 
     */
    public Optional<Output<String>> externalDbSystemId() {
        return Optional.ofNullable(this.externalDbSystemId);
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
     * The current lifecycle state of the external DB system connector.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state of the external DB system connector.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the connectionStatus of the external DB system connector was last updated.
     * 
     */
    @Import(name="timeConnectionStatusLastUpdated")
    private @Nullable Output<String> timeConnectionStatusLastUpdated;

    /**
     * @return The date and time the connectionStatus of the external DB system connector was last updated.
     * 
     */
    public Optional<Output<String>> timeConnectionStatusLastUpdated() {
        return Optional.ofNullable(this.timeConnectionStatusLastUpdated);
    }

    /**
     * The date and time the external DB system connector was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the external DB system connector was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The date and time the external DB system connector was last updated.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The date and time the external DB system connector was last updated.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private ExternalDbSystemConnectorState() {}

    private ExternalDbSystemConnectorState(ExternalDbSystemConnectorState $) {
        this.agentId = $.agentId;
        this.compartmentId = $.compartmentId;
        this.connectionFailureMessage = $.connectionFailureMessage;
        this.connectionInfos = $.connectionInfos;
        this.connectionStatus = $.connectionStatus;
        this.connectorType = $.connectorType;
        this.displayName = $.displayName;
        this.externalDbSystemId = $.externalDbSystemId;
        this.lifecycleDetails = $.lifecycleDetails;
        this.state = $.state;
        this.timeConnectionStatusLastUpdated = $.timeConnectionStatusLastUpdated;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalDbSystemConnectorState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalDbSystemConnectorState $;

        public Builder() {
            $ = new ExternalDbSystemConnectorState();
        }

        public Builder(ExternalDbSystemConnectorState defaults) {
            $ = new ExternalDbSystemConnectorState(Objects.requireNonNull(defaults));
        }

        /**
         * @param agentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
         * 
         * @return builder
         * 
         */
        public Builder agentId(@Nullable Output<String> agentId) {
            $.agentId = agentId;
            return this;
        }

        /**
         * @param agentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system connector.
         * 
         * @return builder
         * 
         */
        public Builder agentId(String agentId) {
            return agentId(Output.of(agentId));
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
         * @param connectionFailureMessage The error message indicating the reason for connection failure or `null` if the connection was successful.
         * 
         * @return builder
         * 
         */
        public Builder connectionFailureMessage(@Nullable Output<String> connectionFailureMessage) {
            $.connectionFailureMessage = connectionFailureMessage;
            return this;
        }

        /**
         * @param connectionFailureMessage The error message indicating the reason for connection failure or `null` if the connection was successful.
         * 
         * @return builder
         * 
         */
        public Builder connectionFailureMessage(String connectionFailureMessage) {
            return connectionFailureMessage(Output.of(connectionFailureMessage));
        }

        /**
         * @param connectionInfos The connection details required to connect to an external DB system component.
         * 
         * @return builder
         * 
         */
        public Builder connectionInfos(@Nullable Output<List<ExternalDbSystemConnectorConnectionInfoArgs>> connectionInfos) {
            $.connectionInfos = connectionInfos;
            return this;
        }

        /**
         * @param connectionInfos The connection details required to connect to an external DB system component.
         * 
         * @return builder
         * 
         */
        public Builder connectionInfos(List<ExternalDbSystemConnectorConnectionInfoArgs> connectionInfos) {
            return connectionInfos(Output.of(connectionInfos));
        }

        /**
         * @param connectionInfos The connection details required to connect to an external DB system component.
         * 
         * @return builder
         * 
         */
        public Builder connectionInfos(ExternalDbSystemConnectorConnectionInfoArgs... connectionInfos) {
            return connectionInfos(List.of(connectionInfos));
        }

        /**
         * @param connectionStatus The status of connectivity to the external DB system component.
         * 
         * @return builder
         * 
         */
        public Builder connectionStatus(@Nullable Output<String> connectionStatus) {
            $.connectionStatus = connectionStatus;
            return this;
        }

        /**
         * @param connectionStatus The status of connectivity to the external DB system component.
         * 
         * @return builder
         * 
         */
        public Builder connectionStatus(String connectionStatus) {
            return connectionStatus(Output.of(connectionStatus));
        }

        /**
         * @param connectorType (Updatable) The type of connector.
         * 
         * @return builder
         * 
         */
        public Builder connectorType(@Nullable Output<String> connectorType) {
            $.connectorType = connectorType;
            return this;
        }

        /**
         * @param connectorType (Updatable) The type of connector.
         * 
         * @return builder
         * 
         */
        public Builder connectorType(String connectorType) {
            return connectorType(Output.of(connectorType));
        }

        /**
         * @param displayName The user-friendly name for the external connector. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName The user-friendly name for the external connector. The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param externalDbSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
         * 
         * @return builder
         * 
         */
        public Builder externalDbSystemId(@Nullable Output<String> externalDbSystemId) {
            $.externalDbSystemId = externalDbSystemId;
            return this;
        }

        /**
         * @param externalDbSystemId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
         * 
         * @return builder
         * 
         */
        public Builder externalDbSystemId(String externalDbSystemId) {
            return externalDbSystemId(Output.of(externalDbSystemId));
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
         * @param state The current lifecycle state of the external DB system connector.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state of the external DB system connector.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeConnectionStatusLastUpdated The date and time the connectionStatus of the external DB system connector was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeConnectionStatusLastUpdated(@Nullable Output<String> timeConnectionStatusLastUpdated) {
            $.timeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
            return this;
        }

        /**
         * @param timeConnectionStatusLastUpdated The date and time the connectionStatus of the external DB system connector was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeConnectionStatusLastUpdated(String timeConnectionStatusLastUpdated) {
            return timeConnectionStatusLastUpdated(Output.of(timeConnectionStatusLastUpdated));
        }

        /**
         * @param timeCreated The date and time the external DB system connector was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the external DB system connector was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The date and time the external DB system connector was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The date and time the external DB system connector was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public ExternalDbSystemConnectorState build() {
            return $;
        }
    }

}