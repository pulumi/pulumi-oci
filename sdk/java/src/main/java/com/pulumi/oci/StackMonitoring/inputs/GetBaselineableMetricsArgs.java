// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.StackMonitoring.inputs.GetBaselineableMetricsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBaselineableMetricsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBaselineableMetricsArgs Empty = new GetBaselineableMetricsArgs();

    /**
     * Identifier for the metric
     * 
     */
    @Import(name="baselineableMetricId")
    private @Nullable Output<String> baselineableMetricId;

    /**
     * @return Identifier for the metric
     * 
     */
    public Optional<Output<String>> baselineableMetricId() {
        return Optional.ofNullable(this.baselineableMetricId);
    }

    /**
     * The ID of the compartment in which data is listed.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which data is listed.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetBaselineableMetricsFilterArgs>> filters;

    public Optional<Output<List<GetBaselineableMetricsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return monitored resource types that has the matching namespace.
     * 
     */
    @Import(name="metricNamespace")
    private @Nullable Output<String> metricNamespace;

    /**
     * @return A filter to return monitored resource types that has the matching namespace.
     * 
     */
    public Optional<Output<String>> metricNamespace() {
        return Optional.ofNullable(this.metricNamespace);
    }

    /**
     * Metric Name
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Metric Name
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Resource Group
     * 
     */
    @Import(name="resourceGroup")
    private @Nullable Output<String> resourceGroup;

    /**
     * @return Resource Group
     * 
     */
    public Optional<Output<String>> resourceGroup() {
        return Optional.ofNullable(this.resourceGroup);
    }

    private GetBaselineableMetricsArgs() {}

    private GetBaselineableMetricsArgs(GetBaselineableMetricsArgs $) {
        this.baselineableMetricId = $.baselineableMetricId;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.metricNamespace = $.metricNamespace;
        this.name = $.name;
        this.resourceGroup = $.resourceGroup;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBaselineableMetricsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBaselineableMetricsArgs $;

        public Builder() {
            $ = new GetBaselineableMetricsArgs();
        }

        public Builder(GetBaselineableMetricsArgs defaults) {
            $ = new GetBaselineableMetricsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param baselineableMetricId Identifier for the metric
         * 
         * @return builder
         * 
         */
        public Builder baselineableMetricId(@Nullable Output<String> baselineableMetricId) {
            $.baselineableMetricId = baselineableMetricId;
            return this;
        }

        /**
         * @param baselineableMetricId Identifier for the metric
         * 
         * @return builder
         * 
         */
        public Builder baselineableMetricId(String baselineableMetricId) {
            return baselineableMetricId(Output.of(baselineableMetricId));
        }

        /**
         * @param compartmentId The ID of the compartment in which data is listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which data is listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetBaselineableMetricsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetBaselineableMetricsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetBaselineableMetricsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param metricNamespace A filter to return monitored resource types that has the matching namespace.
         * 
         * @return builder
         * 
         */
        public Builder metricNamespace(@Nullable Output<String> metricNamespace) {
            $.metricNamespace = metricNamespace;
            return this;
        }

        /**
         * @param metricNamespace A filter to return monitored resource types that has the matching namespace.
         * 
         * @return builder
         * 
         */
        public Builder metricNamespace(String metricNamespace) {
            return metricNamespace(Output.of(metricNamespace));
        }

        /**
         * @param name Metric Name
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Metric Name
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param resourceGroup Resource Group
         * 
         * @return builder
         * 
         */
        public Builder resourceGroup(@Nullable Output<String> resourceGroup) {
            $.resourceGroup = resourceGroup;
            return this;
        }

        /**
         * @param resourceGroup Resource Group
         * 
         * @return builder
         * 
         */
        public Builder resourceGroup(String resourceGroup) {
            return resourceGroup(Output.of(resourceGroup));
        }

        public GetBaselineableMetricsArgs build() {
            return $;
        }
    }

}