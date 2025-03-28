// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmConfig.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApmConfig.outputs.GetConfigsConfigCollection;
import com.pulumi.oci.ApmConfig.outputs.GetConfigsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetConfigsResult {
    private String apmDomainId;
    /**
     * @return The list of config_collection.
     * 
     */
    private List<GetConfigsConfigCollection> configCollections;
    /**
     * @return The type of configuration item.
     * 
     */
    private @Nullable String configType;
    private @Nullable List<String> definedTagEquals;
    private @Nullable List<String> definedTagExists;
    /**
     * @return The name by which a configuration entity is displayed to the end user.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetConfigsFilter> filters;
    private @Nullable List<String> freeformTagEquals;
    private @Nullable List<String> freeformTagExists;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return A string that specifies the group that an OPTIONS item belongs to.
     * 
     */
    private @Nullable String optionsGroup;

    private GetConfigsResult() {}
    public String apmDomainId() {
        return this.apmDomainId;
    }
    /**
     * @return The list of config_collection.
     * 
     */
    public List<GetConfigsConfigCollection> configCollections() {
        return this.configCollections;
    }
    /**
     * @return The type of configuration item.
     * 
     */
    public Optional<String> configType() {
        return Optional.ofNullable(this.configType);
    }
    public List<String> definedTagEquals() {
        return this.definedTagEquals == null ? List.of() : this.definedTagEquals;
    }
    public List<String> definedTagExists() {
        return this.definedTagExists == null ? List.of() : this.definedTagExists;
    }
    /**
     * @return The name by which a configuration entity is displayed to the end user.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetConfigsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    public List<String> freeformTagEquals() {
        return this.freeformTagEquals == null ? List.of() : this.freeformTagEquals;
    }
    public List<String> freeformTagExists() {
        return this.freeformTagExists == null ? List.of() : this.freeformTagExists;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return A string that specifies the group that an OPTIONS item belongs to.
     * 
     */
    public Optional<String> optionsGroup() {
        return Optional.ofNullable(this.optionsGroup);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apmDomainId;
        private List<GetConfigsConfigCollection> configCollections;
        private @Nullable String configType;
        private @Nullable List<String> definedTagEquals;
        private @Nullable List<String> definedTagExists;
        private @Nullable String displayName;
        private @Nullable List<GetConfigsFilter> filters;
        private @Nullable List<String> freeformTagEquals;
        private @Nullable List<String> freeformTagExists;
        private String id;
        private @Nullable String optionsGroup;
        public Builder() {}
        public Builder(GetConfigsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apmDomainId = defaults.apmDomainId;
    	      this.configCollections = defaults.configCollections;
    	      this.configType = defaults.configType;
    	      this.definedTagEquals = defaults.definedTagEquals;
    	      this.definedTagExists = defaults.definedTagExists;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.freeformTagEquals = defaults.freeformTagEquals;
    	      this.freeformTagExists = defaults.freeformTagExists;
    	      this.id = defaults.id;
    	      this.optionsGroup = defaults.optionsGroup;
        }

        @CustomType.Setter
        public Builder apmDomainId(String apmDomainId) {
            if (apmDomainId == null) {
              throw new MissingRequiredPropertyException("GetConfigsResult", "apmDomainId");
            }
            this.apmDomainId = apmDomainId;
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
        public Builder configType(@Nullable String configType) {

            this.configType = configType;
            return this;
        }
        @CustomType.Setter
        public Builder definedTagEquals(@Nullable List<String> definedTagEquals) {

            this.definedTagEquals = definedTagEquals;
            return this;
        }
        public Builder definedTagEquals(String... definedTagEquals) {
            return definedTagEquals(List.of(definedTagEquals));
        }
        @CustomType.Setter
        public Builder definedTagExists(@Nullable List<String> definedTagExists) {

            this.definedTagExists = definedTagExists;
            return this;
        }
        public Builder definedTagExists(String... definedTagExists) {
            return definedTagExists(List.of(definedTagExists));
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
        public Builder freeformTagEquals(@Nullable List<String> freeformTagEquals) {

            this.freeformTagEquals = freeformTagEquals;
            return this;
        }
        public Builder freeformTagEquals(String... freeformTagEquals) {
            return freeformTagEquals(List.of(freeformTagEquals));
        }
        @CustomType.Setter
        public Builder freeformTagExists(@Nullable List<String> freeformTagExists) {

            this.freeformTagExists = freeformTagExists;
            return this;
        }
        public Builder freeformTagExists(String... freeformTagExists) {
            return freeformTagExists(List.of(freeformTagExists));
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
        public Builder optionsGroup(@Nullable String optionsGroup) {

            this.optionsGroup = optionsGroup;
            return this;
        }
        public GetConfigsResult build() {
            final var _resultValue = new GetConfigsResult();
            _resultValue.apmDomainId = apmDomainId;
            _resultValue.configCollections = configCollections;
            _resultValue.configType = configType;
            _resultValue.definedTagEquals = definedTagEquals;
            _resultValue.definedTagExists = definedTagExists;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.freeformTagEquals = freeformTagEquals;
            _resultValue.freeformTagExists = freeformTagExists;
            _resultValue.id = id;
            _resultValue.optionsGroup = optionsGroup;
            return _resultValue;
        }
    }
}
