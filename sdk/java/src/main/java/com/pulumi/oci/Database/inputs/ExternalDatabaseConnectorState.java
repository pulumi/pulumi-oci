// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.ExternalDatabaseConnectorConnectionCredentialsArgs;
import com.pulumi.oci.Database.inputs.ExternalDatabaseConnectorConnectionStringArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalDatabaseConnectorState extends com.pulumi.resources.ResourceArgs {

    public static final ExternalDatabaseConnectorState Empty = new ExternalDatabaseConnectorState();

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
     * (Updatable) Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
     * 
     */
    @Import(name="connectionCredentials")
    private @Nullable Output<ExternalDatabaseConnectorConnectionCredentialsArgs> connectionCredentials;

    /**
     * @return (Updatable) Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
     * 
     */
    public Optional<Output<ExternalDatabaseConnectorConnectionCredentialsArgs>> connectionCredentials() {
        return Optional.ofNullable(this.connectionCredentials);
    }

    /**
     * The status of connectivity to the external database.
     * 
     */
    @Import(name="connectionStatus")
    private @Nullable Output<String> connectionStatus;

    /**
     * @return The status of connectivity to the external database.
     * 
     */
    public Optional<Output<String>> connectionStatus() {
        return Optional.ofNullable(this.connectionStatus);
    }

    /**
     * (Updatable) The Oracle Database connection string.
     * 
     */
    @Import(name="connectionString")
    private @Nullable Output<ExternalDatabaseConnectorConnectionStringArgs> connectionString;

    /**
     * @return (Updatable) The Oracle Database connection string.
     * 
     */
    public Optional<Output<ExternalDatabaseConnectorConnectionStringArgs>> connectionString() {
        return Optional.ofNullable(this.connectionString);
    }

    /**
     * The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    @Import(name="connectorAgentId")
    private @Nullable Output<String> connectorAgentId;

    /**
     * @return The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
     * 
     */
    public Optional<Output<String>> connectorAgentId() {
        return Optional.ofNullable(this.connectorAgentId);
    }

    /**
     * (Updatable) The type of connector used by the external database resource.
     * 
     */
    @Import(name="connectorType")
    private @Nullable Output<String> connectorType;

    /**
     * @return (Updatable) The type of connector used by the external database resource.
     * 
     */
    public Optional<Output<String>> connectorType() {
        return Optional.ofNullable(this.connectorType);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
     * 
     */
    @Import(name="externalDatabaseId")
    private @Nullable Output<String> externalDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
     * 
     */
    public Optional<Output<String>> externalDatabaseId() {
        return Optional.ofNullable(this.externalDatabaseId);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
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
     * The current lifecycle state of the external database connector resource.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current lifecycle state of the external database connector resource.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The date and time the `connectionStatus` of this external connector was last updated.
     * 
     */
    @Import(name="timeConnectionStatusLastUpdated")
    private @Nullable Output<String> timeConnectionStatusLastUpdated;

    /**
     * @return The date and time the `connectionStatus` of this external connector was last updated.
     * 
     */
    public Optional<Output<String>> timeConnectionStatusLastUpdated() {
        return Optional.ofNullable(this.timeConnectionStatusLastUpdated);
    }

    /**
     * The date and time the external connector was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the external connector was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private ExternalDatabaseConnectorState() {}

    private ExternalDatabaseConnectorState(ExternalDatabaseConnectorState $) {
        this.compartmentId = $.compartmentId;
        this.connectionCredentials = $.connectionCredentials;
        this.connectionStatus = $.connectionStatus;
        this.connectionString = $.connectionString;
        this.connectorAgentId = $.connectorAgentId;
        this.connectorType = $.connectorType;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.externalDatabaseId = $.externalDatabaseId;
        this.freeformTags = $.freeformTags;
        this.lifecycleDetails = $.lifecycleDetails;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeConnectionStatusLastUpdated = $.timeConnectionStatusLastUpdated;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalDatabaseConnectorState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalDatabaseConnectorState $;

        public Builder() {
            $ = new ExternalDatabaseConnectorState();
        }

        public Builder(ExternalDatabaseConnectorState defaults) {
            $ = new ExternalDatabaseConnectorState(Objects.requireNonNull(defaults));
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
         * @param connectionCredentials (Updatable) Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
         * 
         * @return builder
         * 
         */
        public Builder connectionCredentials(@Nullable Output<ExternalDatabaseConnectorConnectionCredentialsArgs> connectionCredentials) {
            $.connectionCredentials = connectionCredentials;
            return this;
        }

        /**
         * @param connectionCredentials (Updatable) Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
         * 
         * @return builder
         * 
         */
        public Builder connectionCredentials(ExternalDatabaseConnectorConnectionCredentialsArgs connectionCredentials) {
            return connectionCredentials(Output.of(connectionCredentials));
        }

        /**
         * @param connectionStatus The status of connectivity to the external database.
         * 
         * @return builder
         * 
         */
        public Builder connectionStatus(@Nullable Output<String> connectionStatus) {
            $.connectionStatus = connectionStatus;
            return this;
        }

        /**
         * @param connectionStatus The status of connectivity to the external database.
         * 
         * @return builder
         * 
         */
        public Builder connectionStatus(String connectionStatus) {
            return connectionStatus(Output.of(connectionStatus));
        }

        /**
         * @param connectionString (Updatable) The Oracle Database connection string.
         * 
         * @return builder
         * 
         */
        public Builder connectionString(@Nullable Output<ExternalDatabaseConnectorConnectionStringArgs> connectionString) {
            $.connectionString = connectionString;
            return this;
        }

        /**
         * @param connectionString (Updatable) The Oracle Database connection string.
         * 
         * @return builder
         * 
         */
        public Builder connectionString(ExternalDatabaseConnectorConnectionStringArgs connectionString) {
            return connectionString(Output.of(connectionString));
        }

        /**
         * @param connectorAgentId The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
         * 
         * @return builder
         * 
         */
        public Builder connectorAgentId(@Nullable Output<String> connectorAgentId) {
            $.connectorAgentId = connectorAgentId;
            return this;
        }

        /**
         * @param connectorAgentId The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
         * 
         * @return builder
         * 
         */
        public Builder connectorAgentId(String connectorAgentId) {
            return connectorAgentId(Output.of(connectorAgentId));
        }

        /**
         * @param connectorType (Updatable) The type of connector used by the external database resource.
         * 
         * @return builder
         * 
         */
        public Builder connectorType(@Nullable Output<String> connectorType) {
            $.connectorType = connectorType;
            return this;
        }

        /**
         * @param connectorType (Updatable) The type of connector used by the external database resource.
         * 
         * @return builder
         * 
         */
        public Builder connectorType(String connectorType) {
            return connectorType(Output.of(connectorType));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param externalDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
         * 
         * @return builder
         * 
         */
        public Builder externalDatabaseId(@Nullable Output<String> externalDatabaseId) {
            $.externalDatabaseId = externalDatabaseId;
            return this;
        }

        /**
         * @param externalDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
         * 
         * @return builder
         * 
         */
        public Builder externalDatabaseId(String externalDatabaseId) {
            return externalDatabaseId(Output.of(externalDatabaseId));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
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
         * @param state The current lifecycle state of the external database connector resource.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current lifecycle state of the external database connector resource.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeConnectionStatusLastUpdated The date and time the `connectionStatus` of this external connector was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeConnectionStatusLastUpdated(@Nullable Output<String> timeConnectionStatusLastUpdated) {
            $.timeConnectionStatusLastUpdated = timeConnectionStatusLastUpdated;
            return this;
        }

        /**
         * @param timeConnectionStatusLastUpdated The date and time the `connectionStatus` of this external connector was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeConnectionStatusLastUpdated(String timeConnectionStatusLastUpdated) {
            return timeConnectionStatusLastUpdated(Output.of(timeConnectionStatusLastUpdated));
        }

        /**
         * @param timeCreated The date and time the external connector was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the external connector was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public ExternalDatabaseConnectorState build() {
            return $;
        }
    }

}
