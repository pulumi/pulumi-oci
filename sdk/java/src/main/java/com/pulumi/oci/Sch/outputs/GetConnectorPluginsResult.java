// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Sch.outputs.GetConnectorPluginsConnectorPluginCollection;
import com.pulumi.oci.Sch.outputs.GetConnectorPluginsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetConnectorPluginsResult {
    /**
     * @return The list of connector_plugin_collection.
     * 
     */
    private List<GetConnectorPluginsConnectorPluginCollection> connectorPluginCollections;
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetConnectorPluginsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The service to be called by the connector plugin. Example: `QueueSource`
     * 
     */
    private @Nullable String name;
    /**
     * @return The current state of the service connector.
     * 
     */
    private @Nullable String state;

    private GetConnectorPluginsResult() {}
    /**
     * @return The list of connector_plugin_collection.
     * 
     */
    public List<GetConnectorPluginsConnectorPluginCollection> connectorPluginCollections() {
        return this.connectorPluginCollections;
    }
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetConnectorPluginsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The service to be called by the connector plugin. Example: `QueueSource`
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The current state of the service connector.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConnectorPluginsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetConnectorPluginsConnectorPluginCollection> connectorPluginCollections;
        private @Nullable String displayName;
        private @Nullable List<GetConnectorPluginsFilter> filters;
        private String id;
        private @Nullable String name;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetConnectorPluginsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectorPluginCollections = defaults.connectorPluginCollections;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder connectorPluginCollections(List<GetConnectorPluginsConnectorPluginCollection> connectorPluginCollections) {
            if (connectorPluginCollections == null) {
              throw new MissingRequiredPropertyException("GetConnectorPluginsResult", "connectorPluginCollections");
            }
            this.connectorPluginCollections = connectorPluginCollections;
            return this;
        }
        public Builder connectorPluginCollections(GetConnectorPluginsConnectorPluginCollection... connectorPluginCollections) {
            return connectorPluginCollections(List.of(connectorPluginCollections));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetConnectorPluginsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetConnectorPluginsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetConnectorPluginsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetConnectorPluginsResult build() {
            final var _resultValue = new GetConnectorPluginsResult();
            _resultValue.connectorPluginCollections = connectorPluginCollections;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.name = name;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
