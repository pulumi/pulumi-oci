// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsObjectCollectionRulesFilter;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetLogAnalyticsObjectCollectionRulesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     * 
     */
    private final String compartmentId;
    private final @Nullable List<GetLogAnalyticsObjectCollectionRulesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of log_analytics_object_collection_rule_collection.
     * 
     */
    private final List<GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollection> logAnalyticsObjectCollectionRuleCollections;
    /**
     * @return A unique name to the rule. The name must be unique, within the tenancy, and cannot be changed.
     * 
     */
    private final @Nullable String name;
    private final String namespace;
    /**
     * @return The current state of the rule.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetLogAnalyticsObjectCollectionRulesResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetLogAnalyticsObjectCollectionRulesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("logAnalyticsObjectCollectionRuleCollections") List<GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollection> logAnalyticsObjectCollectionRuleCollections,
        @CustomType.Parameter("name") @Nullable String name,
        @CustomType.Parameter("namespace") String namespace,
        @CustomType.Parameter("state") @Nullable String state) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.logAnalyticsObjectCollectionRuleCollections = logAnalyticsObjectCollectionRuleCollections;
        this.name = name;
        this.namespace = namespace;
        this.state = state;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetLogAnalyticsObjectCollectionRulesFilter> filters() {
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
     * @return The list of log_analytics_object_collection_rule_collection.
     * 
     */
    public List<GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollection> logAnalyticsObjectCollectionRuleCollections() {
        return this.logAnalyticsObjectCollectionRuleCollections;
    }
    /**
     * @return A unique name to the rule. The name must be unique, within the tenancy, and cannot be changed.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The current state of the rule.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogAnalyticsObjectCollectionRulesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetLogAnalyticsObjectCollectionRulesFilter> filters;
        private String id;
        private List<GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollection> logAnalyticsObjectCollectionRuleCollections;
        private @Nullable String name;
        private String namespace;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetLogAnalyticsObjectCollectionRulesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.logAnalyticsObjectCollectionRuleCollections = defaults.logAnalyticsObjectCollectionRuleCollections;
    	      this.name = defaults.name;
    	      this.namespace = defaults.namespace;
    	      this.state = defaults.state;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetLogAnalyticsObjectCollectionRulesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetLogAnalyticsObjectCollectionRulesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder logAnalyticsObjectCollectionRuleCollections(List<GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollection> logAnalyticsObjectCollectionRuleCollections) {
            this.logAnalyticsObjectCollectionRuleCollections = Objects.requireNonNull(logAnalyticsObjectCollectionRuleCollections);
            return this;
        }
        public Builder logAnalyticsObjectCollectionRuleCollections(GetLogAnalyticsObjectCollectionRulesLogAnalyticsObjectCollectionRuleCollection... logAnalyticsObjectCollectionRuleCollections) {
            return logAnalyticsObjectCollectionRuleCollections(List.of(logAnalyticsObjectCollectionRuleCollections));
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetLogAnalyticsObjectCollectionRulesResult build() {
            return new GetLogAnalyticsObjectCollectionRulesResult(compartmentId, filters, id, logAnalyticsObjectCollectionRuleCollections, name, namespace, state);
        }
    }
}
