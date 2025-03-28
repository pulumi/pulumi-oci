// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.outputs.GetConfigsConfigCollection;
import com.pulumi.oci.StackMonitoring.outputs.GetConfigsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetConfigsResult {
    /**
     * @return The OCID of the compartment containing the configuration.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of config_collection.
     * 
     */
    private List<GetConfigsConfigCollection> configCollections;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetConfigsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the configuration.
     * 
     */
    private @Nullable String state;
    private @Nullable String type;

    private GetConfigsResult() {}
    /**
     * @return The OCID of the compartment containing the configuration.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of config_collection.
     * 
     */
    public List<GetConfigsConfigCollection> configCollections() {
        return this.configCollections;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetConfigsFilter> filters() {
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
     * @return The current state of the configuration.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetConfigsConfigCollection> configCollections;
        private @Nullable String displayName;
        private @Nullable List<GetConfigsFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String type;
        public Builder() {}
        public Builder(GetConfigsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configCollections = defaults.configCollections;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetConfigsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder configCollections(List<GetConfigsConfigCollection> configCollections) {
            if (configCollections == null) {
              throw new MissingRequiredPropertyException("GetConfigsResult", "configCollections");
            }
            this.configCollections = configCollections;
            return this;
        }
        public Builder configCollections(GetConfigsConfigCollection... configCollections) {
            return configCollections(List.of(configCollections));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetConfigsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetConfigsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetConfigsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {

            this.type = type;
            return this;
        }
        public GetConfigsResult build() {
            final var _resultValue = new GetConfigsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.configCollections = configCollections;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
