// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmConfig;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApmConfig.inputs.ConfigDimensionArgs;
import com.pulumi.oci.ApmConfig.inputs.ConfigMetricArgs;
import com.pulumi.oci.ApmConfig.inputs.ConfigRuleArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigArgs Empty = new ConfigArgs();

    /**
     * (Updatable) The APM Domain Id the request is intended for.
     * 
     */
    @Import(name="apmDomainId", required=true)
    private Output<String> apmDomainId;

    /**
     * @return (Updatable) The APM Domain Id the request is intended for.
     * 
     */
    public Output<String> apmDomainId() {
        return this.apmDomainId;
    }

    /**
     * (Updatable) The type of configuration item
     * 
     */
    @Import(name="configType", required=true)
    private Output<String> configType;

    /**
     * @return (Updatable) The type of configuration item
     * 
     */
    public Output<String> configType() {
        return this.configType;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A description of the metric
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A description of the metric
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A list of dimensions for this metric. Must be NULL at the moment.
     * 
     */
    @Import(name="dimensions")
    private @Nullable Output<List<ConfigDimensionArgs>> dimensions;

    /**
     * @return (Updatable) A list of dimensions for this metric. Must be NULL at the moment.
     * 
     */
    public Optional<Output<List<ConfigDimensionArgs>>> dimensions() {
        return Optional.ofNullable(this.dimensions);
    }

    /**
     * (Updatable) A user-friendly name that provides a short description this rule.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name that provides a short description this rule.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId will be generated when a Span Filter is created.
     * 
     */
    @Import(name="filterId")
    private @Nullable Output<String> filterId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId will be generated when a Span Filter is created.
     * 
     */
    public Optional<Output<String>> filterId() {
        return Optional.ofNullable(this.filterId);
    }

    /**
     * (Updatable) The string that defines the Span Filter expression.
     * 
     */
    @Import(name="filterText")
    private @Nullable Output<String> filterText;

    /**
     * @return (Updatable) The string that defines the Span Filter expression.
     * 
     */
    public Optional<Output<String>> filterText() {
        return Optional.ofNullable(this.filterText);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="metrics")
    private @Nullable Output<List<ConfigMetricArgs>> metrics;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<List<ConfigMetricArgs>>> metrics() {
        return Optional.ofNullable(this.metrics);
    }

    /**
     * (Updatable) The namespace to write the metrics to
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return (Updatable) The namespace to write the metrics to
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * (Updatable) Indicates that this request is a dry-run. If set to &#34;true&#34;, nothing will be modified, only the validation will be performed.
     * 
     */
    @Import(name="opcDryRun")
    private @Nullable Output<String> opcDryRun;

    /**
     * @return (Updatable) Indicates that this request is a dry-run. If set to &#34;true&#34;, nothing will be modified, only the validation will be performed.
     * 
     */
    public Optional<Output<String>> opcDryRun() {
        return Optional.ofNullable(this.opcDryRun);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="rules")
    private @Nullable Output<List<ConfigRuleArgs>> rules;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<List<ConfigRuleArgs>>> rules() {
        return Optional.ofNullable(this.rules);
    }

    private ConfigArgs() {}

    private ConfigArgs(ConfigArgs $) {
        this.apmDomainId = $.apmDomainId;
        this.configType = $.configType;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.dimensions = $.dimensions;
        this.displayName = $.displayName;
        this.filterId = $.filterId;
        this.filterText = $.filterText;
        this.freeformTags = $.freeformTags;
        this.metrics = $.metrics;
        this.namespace = $.namespace;
        this.opcDryRun = $.opcDryRun;
        this.rules = $.rules;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigArgs $;

        public Builder() {
            $ = new ConfigArgs();
        }

        public Builder(ConfigArgs defaults) {
            $ = new ConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param apmDomainId (Updatable) The APM Domain Id the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(Output<String> apmDomainId) {
            $.apmDomainId = apmDomainId;
            return this;
        }

        /**
         * @param apmDomainId (Updatable) The APM Domain Id the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(String apmDomainId) {
            return apmDomainId(Output.of(apmDomainId));
        }

        /**
         * @param configType (Updatable) The type of configuration item
         * 
         * @return builder
         * 
         */
        public Builder configType(Output<String> configType) {
            $.configType = configType;
            return this;
        }

        /**
         * @param configType (Updatable) The type of configuration item
         * 
         * @return builder
         * 
         */
        public Builder configType(String configType) {
            return configType(Output.of(configType));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A description of the metric
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A description of the metric
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param dimensions (Updatable) A list of dimensions for this metric. Must be NULL at the moment.
         * 
         * @return builder
         * 
         */
        public Builder dimensions(@Nullable Output<List<ConfigDimensionArgs>> dimensions) {
            $.dimensions = dimensions;
            return this;
        }

        /**
         * @param dimensions (Updatable) A list of dimensions for this metric. Must be NULL at the moment.
         * 
         * @return builder
         * 
         */
        public Builder dimensions(List<ConfigDimensionArgs> dimensions) {
            return dimensions(Output.of(dimensions));
        }

        /**
         * @param dimensions (Updatable) A list of dimensions for this metric. Must be NULL at the moment.
         * 
         * @return builder
         * 
         */
        public Builder dimensions(ConfigDimensionArgs... dimensions) {
            return dimensions(List.of(dimensions));
        }

        /**
         * @param displayName (Updatable) A user-friendly name that provides a short description this rule.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name that provides a short description this rule.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param filterId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId will be generated when a Span Filter is created.
         * 
         * @return builder
         * 
         */
        public Builder filterId(@Nullable Output<String> filterId) {
            $.filterId = filterId;
            return this;
        }

        /**
         * @param filterId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId will be generated when a Span Filter is created.
         * 
         * @return builder
         * 
         */
        public Builder filterId(String filterId) {
            return filterId(Output.of(filterId));
        }

        /**
         * @param filterText (Updatable) The string that defines the Span Filter expression.
         * 
         * @return builder
         * 
         */
        public Builder filterText(@Nullable Output<String> filterText) {
            $.filterText = filterText;
            return this;
        }

        /**
         * @param filterText (Updatable) The string that defines the Span Filter expression.
         * 
         * @return builder
         * 
         */
        public Builder filterText(String filterText) {
            return filterText(Output.of(filterText));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param metrics (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder metrics(@Nullable Output<List<ConfigMetricArgs>> metrics) {
            $.metrics = metrics;
            return this;
        }

        /**
         * @param metrics (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder metrics(List<ConfigMetricArgs> metrics) {
            return metrics(Output.of(metrics));
        }

        /**
         * @param metrics (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder metrics(ConfigMetricArgs... metrics) {
            return metrics(List.of(metrics));
        }

        /**
         * @param namespace (Updatable) The namespace to write the metrics to
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace (Updatable) The namespace to write the metrics to
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param opcDryRun (Updatable) Indicates that this request is a dry-run. If set to &#34;true&#34;, nothing will be modified, only the validation will be performed.
         * 
         * @return builder
         * 
         */
        public Builder opcDryRun(@Nullable Output<String> opcDryRun) {
            $.opcDryRun = opcDryRun;
            return this;
        }

        /**
         * @param opcDryRun (Updatable) Indicates that this request is a dry-run. If set to &#34;true&#34;, nothing will be modified, only the validation will be performed.
         * 
         * @return builder
         * 
         */
        public Builder opcDryRun(String opcDryRun) {
            return opcDryRun(Output.of(opcDryRun));
        }

        /**
         * @param rules (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder rules(@Nullable Output<List<ConfigRuleArgs>> rules) {
            $.rules = rules;
            return this;
        }

        /**
         * @param rules (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder rules(List<ConfigRuleArgs> rules) {
            return rules(Output.of(rules));
        }

        /**
         * @param rules (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder rules(ConfigRuleArgs... rules) {
            return rules(List.of(rules));
        }

        public ConfigArgs build() {
            $.apmDomainId = Objects.requireNonNull($.apmDomainId, "expected parameter 'apmDomainId' to be non-null");
            $.configType = Objects.requireNonNull($.configType, "expected parameter 'configType' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            return $;
        }
    }

}
