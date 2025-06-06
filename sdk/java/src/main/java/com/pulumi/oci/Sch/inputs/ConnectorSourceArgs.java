// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Sch.inputs.ConnectorSourceCursorArgs;
import com.pulumi.oci.Sch.inputs.ConnectorSourceLogSourceArgs;
import com.pulumi.oci.Sch.inputs.ConnectorSourceMonitoringSourceArgs;
import com.pulumi.oci.Sch.inputs.ConnectorSourcePrivateEndpointMetadataArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConnectorSourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConnectorSourceArgs Empty = new ConnectorSourceArgs();

    /**
     * (Updatable) The configuration map for the connector plugin. This map includes parameters specific to the connector plugin type.  For example, for `QueueSource`, the map lists the OCID of the selected queue. To find the parameters for a connector plugin, get the plugin using [GetConnectorPlugin](https://docs.cloud.oracle.com/iaas/api/#/en/serviceconnectors/latest/ConnectorPlugin/GetConnectorPlugin) and review its schema value.
     * 
     */
    @Import(name="configMap")
    private @Nullable Output<String> configMap;

    /**
     * @return (Updatable) The configuration map for the connector plugin. This map includes parameters specific to the connector plugin type.  For example, for `QueueSource`, the map lists the OCID of the selected queue. To find the parameters for a connector plugin, get the plugin using [GetConnectorPlugin](https://docs.cloud.oracle.com/iaas/api/#/en/serviceconnectors/latest/ConnectorPlugin/GetConnectorPlugin) and review its schema value.
     * 
     */
    public Optional<Output<String>> configMap() {
        return Optional.ofNullable(this.configMap);
    }

    /**
     * (Updatable) The [read setting](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector-streaming-source.htm), which determines where in the stream to start moving data. For configuration instructions, see [Creating a Connector with a Streaming Source](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector-streaming-source.htm).
     * 
     */
    @Import(name="cursor")
    private @Nullable Output<ConnectorSourceCursorArgs> cursor;

    /**
     * @return (Updatable) The [read setting](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector-streaming-source.htm), which determines where in the stream to start moving data. For configuration instructions, see [Creating a Connector with a Streaming Source](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector-streaming-source.htm).
     * 
     */
    public Optional<Output<ConnectorSourceCursorArgs>> cursor() {
        return Optional.ofNullable(this.cursor);
    }

    /**
     * (Updatable) The type discriminator.
     * 
     */
    @Import(name="kind", required=true)
    private Output<String> kind;

    /**
     * @return (Updatable) The type discriminator.
     * 
     */
    public Output<String> kind() {
        return this.kind;
    }

    /**
     * (Updatable) The logs for this Logging source.
     * 
     */
    @Import(name="logSources")
    private @Nullable Output<List<ConnectorSourceLogSourceArgs>> logSources;

    /**
     * @return (Updatable) The logs for this Logging source.
     * 
     */
    public Optional<Output<List<ConnectorSourceLogSourceArgs>>> logSources() {
        return Optional.ofNullable(this.logSources);
    }

    /**
     * (Updatable) One or more compartment-specific lists of metric namespaces to retrieve data from.
     * 
     */
    @Import(name="monitoringSources")
    private @Nullable Output<List<ConnectorSourceMonitoringSourceArgs>> monitoringSources;

    /**
     * @return (Updatable) One or more compartment-specific lists of metric namespaces to retrieve data from.
     * 
     */
    public Optional<Output<List<ConnectorSourceMonitoringSourceArgs>>> monitoringSources() {
        return Optional.ofNullable(this.monitoringSources);
    }

    /**
     * (Updatable) The name of the connector plugin. This name indicates the service to be called by the connector plugin. For example, `QueueSource` indicates the Queue service. To find names of connector plugins, list the plugin using [ListConnectorPlugin](https://docs.cloud.oracle.com/iaas/api/#/en/serviceconnectors/latest/ConnectorPluginSummary/ListConnectorPlugins).
     * 
     */
    @Import(name="pluginName")
    private @Nullable Output<String> pluginName;

    /**
     * @return (Updatable) The name of the connector plugin. This name indicates the service to be called by the connector plugin. For example, `QueueSource` indicates the Queue service. To find names of connector plugins, list the plugin using [ListConnectorPlugin](https://docs.cloud.oracle.com/iaas/api/#/en/serviceconnectors/latest/ConnectorPluginSummary/ListConnectorPlugins).
     * 
     */
    public Optional<Output<String>> pluginName() {
        return Optional.ofNullable(this.pluginName);
    }

    /**
     * The private endpoint metadata for the connector&#39;s source or target.
     * 
     */
    @Import(name="privateEndpointMetadatas")
    private @Nullable Output<List<ConnectorSourcePrivateEndpointMetadataArgs>> privateEndpointMetadatas;

    /**
     * @return The private endpoint metadata for the connector&#39;s source or target.
     * 
     */
    public Optional<Output<List<ConnectorSourcePrivateEndpointMetadataArgs>>> privateEndpointMetadatas() {
        return Optional.ofNullable(this.privateEndpointMetadatas);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream.
     * 
     */
    @Import(name="streamId")
    private @Nullable Output<String> streamId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream.
     * 
     */
    public Optional<Output<String>> streamId() {
        return Optional.ofNullable(this.streamId);
    }

    private ConnectorSourceArgs() {}

    private ConnectorSourceArgs(ConnectorSourceArgs $) {
        this.configMap = $.configMap;
        this.cursor = $.cursor;
        this.kind = $.kind;
        this.logSources = $.logSources;
        this.monitoringSources = $.monitoringSources;
        this.pluginName = $.pluginName;
        this.privateEndpointMetadatas = $.privateEndpointMetadatas;
        this.streamId = $.streamId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConnectorSourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConnectorSourceArgs $;

        public Builder() {
            $ = new ConnectorSourceArgs();
        }

        public Builder(ConnectorSourceArgs defaults) {
            $ = new ConnectorSourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configMap (Updatable) The configuration map for the connector plugin. This map includes parameters specific to the connector plugin type.  For example, for `QueueSource`, the map lists the OCID of the selected queue. To find the parameters for a connector plugin, get the plugin using [GetConnectorPlugin](https://docs.cloud.oracle.com/iaas/api/#/en/serviceconnectors/latest/ConnectorPlugin/GetConnectorPlugin) and review its schema value.
         * 
         * @return builder
         * 
         */
        public Builder configMap(@Nullable Output<String> configMap) {
            $.configMap = configMap;
            return this;
        }

        /**
         * @param configMap (Updatable) The configuration map for the connector plugin. This map includes parameters specific to the connector plugin type.  For example, for `QueueSource`, the map lists the OCID of the selected queue. To find the parameters for a connector plugin, get the plugin using [GetConnectorPlugin](https://docs.cloud.oracle.com/iaas/api/#/en/serviceconnectors/latest/ConnectorPlugin/GetConnectorPlugin) and review its schema value.
         * 
         * @return builder
         * 
         */
        public Builder configMap(String configMap) {
            return configMap(Output.of(configMap));
        }

        /**
         * @param cursor (Updatable) The [read setting](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector-streaming-source.htm), which determines where in the stream to start moving data. For configuration instructions, see [Creating a Connector with a Streaming Source](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector-streaming-source.htm).
         * 
         * @return builder
         * 
         */
        public Builder cursor(@Nullable Output<ConnectorSourceCursorArgs> cursor) {
            $.cursor = cursor;
            return this;
        }

        /**
         * @param cursor (Updatable) The [read setting](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector-streaming-source.htm), which determines where in the stream to start moving data. For configuration instructions, see [Creating a Connector with a Streaming Source](https://docs.cloud.oracle.com/iaas/Content/connector-hub/create-service-connector-streaming-source.htm).
         * 
         * @return builder
         * 
         */
        public Builder cursor(ConnectorSourceCursorArgs cursor) {
            return cursor(Output.of(cursor));
        }

        /**
         * @param kind (Updatable) The type discriminator.
         * 
         * @return builder
         * 
         */
        public Builder kind(Output<String> kind) {
            $.kind = kind;
            return this;
        }

        /**
         * @param kind (Updatable) The type discriminator.
         * 
         * @return builder
         * 
         */
        public Builder kind(String kind) {
            return kind(Output.of(kind));
        }

        /**
         * @param logSources (Updatable) The logs for this Logging source.
         * 
         * @return builder
         * 
         */
        public Builder logSources(@Nullable Output<List<ConnectorSourceLogSourceArgs>> logSources) {
            $.logSources = logSources;
            return this;
        }

        /**
         * @param logSources (Updatable) The logs for this Logging source.
         * 
         * @return builder
         * 
         */
        public Builder logSources(List<ConnectorSourceLogSourceArgs> logSources) {
            return logSources(Output.of(logSources));
        }

        /**
         * @param logSources (Updatable) The logs for this Logging source.
         * 
         * @return builder
         * 
         */
        public Builder logSources(ConnectorSourceLogSourceArgs... logSources) {
            return logSources(List.of(logSources));
        }

        /**
         * @param monitoringSources (Updatable) One or more compartment-specific lists of metric namespaces to retrieve data from.
         * 
         * @return builder
         * 
         */
        public Builder monitoringSources(@Nullable Output<List<ConnectorSourceMonitoringSourceArgs>> monitoringSources) {
            $.monitoringSources = monitoringSources;
            return this;
        }

        /**
         * @param monitoringSources (Updatable) One or more compartment-specific lists of metric namespaces to retrieve data from.
         * 
         * @return builder
         * 
         */
        public Builder monitoringSources(List<ConnectorSourceMonitoringSourceArgs> monitoringSources) {
            return monitoringSources(Output.of(monitoringSources));
        }

        /**
         * @param monitoringSources (Updatable) One or more compartment-specific lists of metric namespaces to retrieve data from.
         * 
         * @return builder
         * 
         */
        public Builder monitoringSources(ConnectorSourceMonitoringSourceArgs... monitoringSources) {
            return monitoringSources(List.of(monitoringSources));
        }

        /**
         * @param pluginName (Updatable) The name of the connector plugin. This name indicates the service to be called by the connector plugin. For example, `QueueSource` indicates the Queue service. To find names of connector plugins, list the plugin using [ListConnectorPlugin](https://docs.cloud.oracle.com/iaas/api/#/en/serviceconnectors/latest/ConnectorPluginSummary/ListConnectorPlugins).
         * 
         * @return builder
         * 
         */
        public Builder pluginName(@Nullable Output<String> pluginName) {
            $.pluginName = pluginName;
            return this;
        }

        /**
         * @param pluginName (Updatable) The name of the connector plugin. This name indicates the service to be called by the connector plugin. For example, `QueueSource` indicates the Queue service. To find names of connector plugins, list the plugin using [ListConnectorPlugin](https://docs.cloud.oracle.com/iaas/api/#/en/serviceconnectors/latest/ConnectorPluginSummary/ListConnectorPlugins).
         * 
         * @return builder
         * 
         */
        public Builder pluginName(String pluginName) {
            return pluginName(Output.of(pluginName));
        }

        /**
         * @param privateEndpointMetadatas The private endpoint metadata for the connector&#39;s source or target.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointMetadatas(@Nullable Output<List<ConnectorSourcePrivateEndpointMetadataArgs>> privateEndpointMetadatas) {
            $.privateEndpointMetadatas = privateEndpointMetadatas;
            return this;
        }

        /**
         * @param privateEndpointMetadatas The private endpoint metadata for the connector&#39;s source or target.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointMetadatas(List<ConnectorSourcePrivateEndpointMetadataArgs> privateEndpointMetadatas) {
            return privateEndpointMetadatas(Output.of(privateEndpointMetadatas));
        }

        /**
         * @param privateEndpointMetadatas The private endpoint metadata for the connector&#39;s source or target.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointMetadatas(ConnectorSourcePrivateEndpointMetadataArgs... privateEndpointMetadatas) {
            return privateEndpointMetadatas(List.of(privateEndpointMetadatas));
        }

        /**
         * @param streamId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream.
         * 
         * @return builder
         * 
         */
        public Builder streamId(@Nullable Output<String> streamId) {
            $.streamId = streamId;
            return this;
        }

        /**
         * @param streamId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream.
         * 
         * @return builder
         * 
         */
        public Builder streamId(String streamId) {
            return streamId(Output.of(streamId));
        }

        public ConnectorSourceArgs build() {
            if ($.kind == null) {
                throw new MissingRequiredPropertyException("ConnectorSourceArgs", "kind");
            }
            return $;
        }
    }

}
