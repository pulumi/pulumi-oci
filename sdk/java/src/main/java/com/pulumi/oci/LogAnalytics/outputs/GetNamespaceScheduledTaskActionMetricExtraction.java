// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNamespaceScheduledTaskActionMetricExtraction {
    /**
     * @return Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String compartmentId;
    /**
     * @return The metric name of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($).
     * 
     */
    private String metricName;
    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    private String namespace;
    /**
     * @return The resource group of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($).
     * 
     */
    private String resourceGroup;

    private GetNamespaceScheduledTaskActionMetricExtraction() {}
    /**
     * @return Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The metric name of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($).
     * 
     */
    public String metricName() {
        return this.metricName;
    }
    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The resource group of the extracted metric. A valid value starts with an alphabetical character and includes only alphanumeric characters, periods (.), underscores (_), hyphens (-), and dollar signs ($).
     * 
     */
    public String resourceGroup() {
        return this.resourceGroup;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceScheduledTaskActionMetricExtraction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String metricName;
        private String namespace;
        private String resourceGroup;
        public Builder() {}
        public Builder(GetNamespaceScheduledTaskActionMetricExtraction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.metricName = defaults.metricName;
    	      this.namespace = defaults.namespace;
    	      this.resourceGroup = defaults.resourceGroup;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder metricName(String metricName) {
            this.metricName = Objects.requireNonNull(metricName);
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder resourceGroup(String resourceGroup) {
            this.resourceGroup = Objects.requireNonNull(resourceGroup);
            return this;
        }
        public GetNamespaceScheduledTaskActionMetricExtraction build() {
            final var o = new GetNamespaceScheduledTaskActionMetricExtraction();
            o.compartmentId = compartmentId;
            o.metricName = metricName;
            o.namespace = namespace;
            o.resourceGroup = resourceGroup;
            return o;
        }
    }
}