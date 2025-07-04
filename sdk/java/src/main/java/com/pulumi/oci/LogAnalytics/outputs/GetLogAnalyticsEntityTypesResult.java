// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsEntityTypesFilter;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsEntityTypesLogAnalyticsEntityTypeCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetLogAnalyticsEntityTypesResult {
    /**
     * @return Log analytics entity type group. This can be CLOUD (OCI) or NON_CLOUD otherwise.
     * 
     */
    private @Nullable String cloudType;
    private @Nullable List<GetLogAnalyticsEntityTypesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of log_analytics_entity_type_collection.
     * 
     */
    private List<GetLogAnalyticsEntityTypesLogAnalyticsEntityTypeCollection> logAnalyticsEntityTypeCollections;
    /**
     * @return Log analytics entity type name.
     * 
     */
    private @Nullable String name;
    private @Nullable String nameContains;
    private String namespace;
    /**
     * @return The current lifecycle state of the log analytics entity type.
     * 
     */
    private @Nullable String state;

    private GetLogAnalyticsEntityTypesResult() {}
    /**
     * @return Log analytics entity type group. This can be CLOUD (OCI) or NON_CLOUD otherwise.
     * 
     */
    public Optional<String> cloudType() {
        return Optional.ofNullable(this.cloudType);
    }
    public List<GetLogAnalyticsEntityTypesFilter> filters() {
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
     * @return The list of log_analytics_entity_type_collection.
     * 
     */
    public List<GetLogAnalyticsEntityTypesLogAnalyticsEntityTypeCollection> logAnalyticsEntityTypeCollections() {
        return this.logAnalyticsEntityTypeCollections;
    }
    /**
     * @return Log analytics entity type name.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    public Optional<String> nameContains() {
        return Optional.ofNullable(this.nameContains);
    }
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The current lifecycle state of the log analytics entity type.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogAnalyticsEntityTypesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String cloudType;
        private @Nullable List<GetLogAnalyticsEntityTypesFilter> filters;
        private String id;
        private List<GetLogAnalyticsEntityTypesLogAnalyticsEntityTypeCollection> logAnalyticsEntityTypeCollections;
        private @Nullable String name;
        private @Nullable String nameContains;
        private String namespace;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetLogAnalyticsEntityTypesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cloudType = defaults.cloudType;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.logAnalyticsEntityTypeCollections = defaults.logAnalyticsEntityTypeCollections;
    	      this.name = defaults.name;
    	      this.nameContains = defaults.nameContains;
    	      this.namespace = defaults.namespace;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder cloudType(@Nullable String cloudType) {

            this.cloudType = cloudType;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetLogAnalyticsEntityTypesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetLogAnalyticsEntityTypesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetLogAnalyticsEntityTypesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder logAnalyticsEntityTypeCollections(List<GetLogAnalyticsEntityTypesLogAnalyticsEntityTypeCollection> logAnalyticsEntityTypeCollections) {
            if (logAnalyticsEntityTypeCollections == null) {
              throw new MissingRequiredPropertyException("GetLogAnalyticsEntityTypesResult", "logAnalyticsEntityTypeCollections");
            }
            this.logAnalyticsEntityTypeCollections = logAnalyticsEntityTypeCollections;
            return this;
        }
        public Builder logAnalyticsEntityTypeCollections(GetLogAnalyticsEntityTypesLogAnalyticsEntityTypeCollection... logAnalyticsEntityTypeCollections) {
            return logAnalyticsEntityTypeCollections(List.of(logAnalyticsEntityTypeCollections));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder nameContains(@Nullable String nameContains) {

            this.nameContains = nameContains;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetLogAnalyticsEntityTypesResult", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetLogAnalyticsEntityTypesResult build() {
            final var _resultValue = new GetLogAnalyticsEntityTypesResult();
            _resultValue.cloudType = cloudType;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.logAnalyticsEntityTypeCollections = logAnalyticsEntityTypeCollections;
            _resultValue.name = name;
            _resultValue.nameContains = nameContains;
            _resultValue.namespace = namespace;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
