// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmConfig.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApmConfig.outputs.GetConfigDimension;
import com.pulumi.oci.ApmConfig.outputs.GetConfigMetric;
import com.pulumi.oci.ApmConfig.outputs.GetConfigRule;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetConfigResult {
    private String apmDomainId;
    private String configId;
    /**
     * @return The type of configuration item.
     * 
     */
    private String configType;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A description of the metric.
     * 
     */
    private String description;
    /**
     * @return A list of dimensions for the metric. This variable should not be used.
     * 
     */
    private List<GetConfigDimension> dimensions;
    /**
     * @return The name by which a configuration entity is displayed to the end user.
     * 
     */
    private String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId is generated when a Span Filter is created.
     * 
     */
    private String filterId;
    /**
     * @return The string that defines the Span Filter expression.
     * 
     */
    private String filterText;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return A string that specifies the group that an OPTIONS item belongs to.
     * 
     */
    private String group;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item. An OCID is generated when the item is created.
     * 
     */
    private String id;
    /**
     * @return The list of metrics in this group.
     * 
     */
    private List<GetConfigMetric> metrics;
    /**
     * @return The namespace to which the metrics are published. It must be one of several predefined namespaces.
     * 
     */
    private String namespace;
    private String opcDryRun;
    /**
     * @return The options are stored here as JSON.
     * 
     */
    private String options;
    private List<GetConfigRule> rules;
    /**
     * @return The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    private String timeUpdated;

    private GetConfigResult() {}
    public String apmDomainId() {
        return this.apmDomainId;
    }
    public String configId() {
        return this.configId;
    }
    /**
     * @return The type of configuration item.
     * 
     */
    public String configType() {
        return this.configType;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A description of the metric.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A list of dimensions for the metric. This variable should not be used.
     * 
     */
    public List<GetConfigDimension> dimensions() {
        return this.dimensions;
    }
    /**
     * @return The name by which a configuration entity is displayed to the end user.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId is generated when a Span Filter is created.
     * 
     */
    public String filterId() {
        return this.filterId;
    }
    /**
     * @return The string that defines the Span Filter expression.
     * 
     */
    public String filterText() {
        return this.filterText;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return A string that specifies the group that an OPTIONS item belongs to.
     * 
     */
    public String group() {
        return this.group;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item. An OCID is generated when the item is created.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of metrics in this group.
     * 
     */
    public List<GetConfigMetric> metrics() {
        return this.metrics;
    }
    /**
     * @return The namespace to which the metrics are published. It must be one of several predefined namespaces.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    public String opcDryRun() {
        return this.opcDryRun;
    }
    /**
     * @return The options are stored here as JSON.
     * 
     */
    public String options() {
        return this.options;
    }
    public List<GetConfigRule> rules() {
        return this.rules;
    }
    /**
     * @return The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apmDomainId;
        private String configId;
        private String configType;
        private Map<String,Object> definedTags;
        private String description;
        private List<GetConfigDimension> dimensions;
        private String displayName;
        private String filterId;
        private String filterText;
        private Map<String,Object> freeformTags;
        private String group;
        private String id;
        private List<GetConfigMetric> metrics;
        private String namespace;
        private String opcDryRun;
        private String options;
        private List<GetConfigRule> rules;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetConfigResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apmDomainId = defaults.apmDomainId;
    	      this.configId = defaults.configId;
    	      this.configType = defaults.configType;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.dimensions = defaults.dimensions;
    	      this.displayName = defaults.displayName;
    	      this.filterId = defaults.filterId;
    	      this.filterText = defaults.filterText;
    	      this.freeformTags = defaults.freeformTags;
    	      this.group = defaults.group;
    	      this.id = defaults.id;
    	      this.metrics = defaults.metrics;
    	      this.namespace = defaults.namespace;
    	      this.opcDryRun = defaults.opcDryRun;
    	      this.options = defaults.options;
    	      this.rules = defaults.rules;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder apmDomainId(String apmDomainId) {
            this.apmDomainId = Objects.requireNonNull(apmDomainId);
            return this;
        }
        @CustomType.Setter
        public Builder configId(String configId) {
            this.configId = Objects.requireNonNull(configId);
            return this;
        }
        @CustomType.Setter
        public Builder configType(String configType) {
            this.configType = Objects.requireNonNull(configType);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder dimensions(List<GetConfigDimension> dimensions) {
            this.dimensions = Objects.requireNonNull(dimensions);
            return this;
        }
        public Builder dimensions(GetConfigDimension... dimensions) {
            return dimensions(List.of(dimensions));
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder filterId(String filterId) {
            this.filterId = Objects.requireNonNull(filterId);
            return this;
        }
        @CustomType.Setter
        public Builder filterText(String filterText) {
            this.filterText = Objects.requireNonNull(filterText);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder group(String group) {
            this.group = Objects.requireNonNull(group);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder metrics(List<GetConfigMetric> metrics) {
            this.metrics = Objects.requireNonNull(metrics);
            return this;
        }
        public Builder metrics(GetConfigMetric... metrics) {
            return metrics(List.of(metrics));
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder opcDryRun(String opcDryRun) {
            this.opcDryRun = Objects.requireNonNull(opcDryRun);
            return this;
        }
        @CustomType.Setter
        public Builder options(String options) {
            this.options = Objects.requireNonNull(options);
            return this;
        }
        @CustomType.Setter
        public Builder rules(List<GetConfigRule> rules) {
            this.rules = Objects.requireNonNull(rules);
            return this;
        }
        public Builder rules(GetConfigRule... rules) {
            return rules(List.of(rules));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetConfigResult build() {
            final var o = new GetConfigResult();
            o.apmDomainId = apmDomainId;
            o.configId = configId;
            o.configType = configType;
            o.definedTags = definedTags;
            o.description = description;
            o.dimensions = dimensions;
            o.displayName = displayName;
            o.filterId = filterId;
            o.filterText = filterText;
            o.freeformTags = freeformTags;
            o.group = group;
            o.id = id;
            o.metrics = metrics;
            o.namespace = namespace;
            o.opcDryRun = opcDryRun;
            o.options = options;
            o.rules = rules;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}