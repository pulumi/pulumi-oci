// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.StackMonitoring.outputs.MetricExtensionQueryPropertiesInParamDetail;
import com.pulumi.oci.StackMonitoring.outputs.MetricExtensionQueryPropertiesOutParamDetails;
import com.pulumi.oci.StackMonitoring.outputs.MetricExtensionQueryPropertiesScriptDetails;
import com.pulumi.oci.StackMonitoring.outputs.MetricExtensionQueryPropertiesSqlDetails;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MetricExtensionQueryProperties {
    /**
     * @return (Updatable) Arguments required by either command or script
     * 
     */
    private @Nullable String arguments;
    /**
     * @return (Updatable) Prefix for an auto generated metric, in case multiple rows with non unique key values are returned
     * 
     */
    private @Nullable String autoRowPrefix;
    /**
     * @return (Updatable) Type of possible collection methods.
     * 
     */
    private String collectionMethod;
    /**
     * @return (Updatable) OS command to execute without arguments
     * 
     */
    private @Nullable String command;
    /**
     * @return (Updatable) Character used to delimit multiple metric values in single line of output
     * 
     */
    private @Nullable String delimiter;
    /**
     * @return (Updatable) Semi-colon separated list of key properties from Managed Bean ObjectName to be used as key metrics
     * 
     */
    private @Nullable String identityMetric;
    /**
     * @return (Updatable) List of values and position of PL/SQL procedure IN parameters
     * 
     */
    private @Nullable List<MetricExtensionQueryPropertiesInParamDetail> inParamDetails;
    /**
     * @return (Updatable) Indicates if Metric Service is enabled on server domain
     * 
     */
    private @Nullable Boolean isMetricServiceEnabled;
    /**
     * @return (Updatable) List of JMX attributes or Metric Service Table columns separated by semi-colon
     * 
     */
    private @Nullable String jmxAttributes;
    /**
     * @return (Updatable) JMX Managed Bean Query or Metric Service Table name
     * 
     */
    private @Nullable String managedBeanQuery;
    /**
     * @return (Updatable) Position and SQL Type of PL/SQL OUT parameter
     * 
     */
    private @Nullable MetricExtensionQueryPropertiesOutParamDetails outParamDetails;
    /**
     * @return (Updatable) Script details applicable to any OS Command based Metric Extension which needs to run a script to collect data
     * 
     */
    private @Nullable MetricExtensionQueryPropertiesScriptDetails scriptDetails;
    /**
     * @return (Updatable) Details of Sql content which needs to execute to collect Metric Extension data
     * 
     */
    private @Nullable MetricExtensionQueryPropertiesSqlDetails sqlDetails;
    /**
     * @return (Updatable) Type of SQL data collection method i.e. either a Statement or SQL Script File
     * 
     */
    private @Nullable String sqlType;
    /**
     * @return (Updatable) String prefix used to identify metric output of the OS Command
     * 
     */
    private @Nullable String startsWith;

    private MetricExtensionQueryProperties() {}
    /**
     * @return (Updatable) Arguments required by either command or script
     * 
     */
    public Optional<String> arguments() {
        return Optional.ofNullable(this.arguments);
    }
    /**
     * @return (Updatable) Prefix for an auto generated metric, in case multiple rows with non unique key values are returned
     * 
     */
    public Optional<String> autoRowPrefix() {
        return Optional.ofNullable(this.autoRowPrefix);
    }
    /**
     * @return (Updatable) Type of possible collection methods.
     * 
     */
    public String collectionMethod() {
        return this.collectionMethod;
    }
    /**
     * @return (Updatable) OS command to execute without arguments
     * 
     */
    public Optional<String> command() {
        return Optional.ofNullable(this.command);
    }
    /**
     * @return (Updatable) Character used to delimit multiple metric values in single line of output
     * 
     */
    public Optional<String> delimiter() {
        return Optional.ofNullable(this.delimiter);
    }
    /**
     * @return (Updatable) Semi-colon separated list of key properties from Managed Bean ObjectName to be used as key metrics
     * 
     */
    public Optional<String> identityMetric() {
        return Optional.ofNullable(this.identityMetric);
    }
    /**
     * @return (Updatable) List of values and position of PL/SQL procedure IN parameters
     * 
     */
    public List<MetricExtensionQueryPropertiesInParamDetail> inParamDetails() {
        return this.inParamDetails == null ? List.of() : this.inParamDetails;
    }
    /**
     * @return (Updatable) Indicates if Metric Service is enabled on server domain
     * 
     */
    public Optional<Boolean> isMetricServiceEnabled() {
        return Optional.ofNullable(this.isMetricServiceEnabled);
    }
    /**
     * @return (Updatable) List of JMX attributes or Metric Service Table columns separated by semi-colon
     * 
     */
    public Optional<String> jmxAttributes() {
        return Optional.ofNullable(this.jmxAttributes);
    }
    /**
     * @return (Updatable) JMX Managed Bean Query or Metric Service Table name
     * 
     */
    public Optional<String> managedBeanQuery() {
        return Optional.ofNullable(this.managedBeanQuery);
    }
    /**
     * @return (Updatable) Position and SQL Type of PL/SQL OUT parameter
     * 
     */
    public Optional<MetricExtensionQueryPropertiesOutParamDetails> outParamDetails() {
        return Optional.ofNullable(this.outParamDetails);
    }
    /**
     * @return (Updatable) Script details applicable to any OS Command based Metric Extension which needs to run a script to collect data
     * 
     */
    public Optional<MetricExtensionQueryPropertiesScriptDetails> scriptDetails() {
        return Optional.ofNullable(this.scriptDetails);
    }
    /**
     * @return (Updatable) Details of Sql content which needs to execute to collect Metric Extension data
     * 
     */
    public Optional<MetricExtensionQueryPropertiesSqlDetails> sqlDetails() {
        return Optional.ofNullable(this.sqlDetails);
    }
    /**
     * @return (Updatable) Type of SQL data collection method i.e. either a Statement or SQL Script File
     * 
     */
    public Optional<String> sqlType() {
        return Optional.ofNullable(this.sqlType);
    }
    /**
     * @return (Updatable) String prefix used to identify metric output of the OS Command
     * 
     */
    public Optional<String> startsWith() {
        return Optional.ofNullable(this.startsWith);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MetricExtensionQueryProperties defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String arguments;
        private @Nullable String autoRowPrefix;
        private String collectionMethod;
        private @Nullable String command;
        private @Nullable String delimiter;
        private @Nullable String identityMetric;
        private @Nullable List<MetricExtensionQueryPropertiesInParamDetail> inParamDetails;
        private @Nullable Boolean isMetricServiceEnabled;
        private @Nullable String jmxAttributes;
        private @Nullable String managedBeanQuery;
        private @Nullable MetricExtensionQueryPropertiesOutParamDetails outParamDetails;
        private @Nullable MetricExtensionQueryPropertiesScriptDetails scriptDetails;
        private @Nullable MetricExtensionQueryPropertiesSqlDetails sqlDetails;
        private @Nullable String sqlType;
        private @Nullable String startsWith;
        public Builder() {}
        public Builder(MetricExtensionQueryProperties defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.arguments = defaults.arguments;
    	      this.autoRowPrefix = defaults.autoRowPrefix;
    	      this.collectionMethod = defaults.collectionMethod;
    	      this.command = defaults.command;
    	      this.delimiter = defaults.delimiter;
    	      this.identityMetric = defaults.identityMetric;
    	      this.inParamDetails = defaults.inParamDetails;
    	      this.isMetricServiceEnabled = defaults.isMetricServiceEnabled;
    	      this.jmxAttributes = defaults.jmxAttributes;
    	      this.managedBeanQuery = defaults.managedBeanQuery;
    	      this.outParamDetails = defaults.outParamDetails;
    	      this.scriptDetails = defaults.scriptDetails;
    	      this.sqlDetails = defaults.sqlDetails;
    	      this.sqlType = defaults.sqlType;
    	      this.startsWith = defaults.startsWith;
        }

        @CustomType.Setter
        public Builder arguments(@Nullable String arguments) {
            this.arguments = arguments;
            return this;
        }
        @CustomType.Setter
        public Builder autoRowPrefix(@Nullable String autoRowPrefix) {
            this.autoRowPrefix = autoRowPrefix;
            return this;
        }
        @CustomType.Setter
        public Builder collectionMethod(String collectionMethod) {
            this.collectionMethod = Objects.requireNonNull(collectionMethod);
            return this;
        }
        @CustomType.Setter
        public Builder command(@Nullable String command) {
            this.command = command;
            return this;
        }
        @CustomType.Setter
        public Builder delimiter(@Nullable String delimiter) {
            this.delimiter = delimiter;
            return this;
        }
        @CustomType.Setter
        public Builder identityMetric(@Nullable String identityMetric) {
            this.identityMetric = identityMetric;
            return this;
        }
        @CustomType.Setter
        public Builder inParamDetails(@Nullable List<MetricExtensionQueryPropertiesInParamDetail> inParamDetails) {
            this.inParamDetails = inParamDetails;
            return this;
        }
        public Builder inParamDetails(MetricExtensionQueryPropertiesInParamDetail... inParamDetails) {
            return inParamDetails(List.of(inParamDetails));
        }
        @CustomType.Setter
        public Builder isMetricServiceEnabled(@Nullable Boolean isMetricServiceEnabled) {
            this.isMetricServiceEnabled = isMetricServiceEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder jmxAttributes(@Nullable String jmxAttributes) {
            this.jmxAttributes = jmxAttributes;
            return this;
        }
        @CustomType.Setter
        public Builder managedBeanQuery(@Nullable String managedBeanQuery) {
            this.managedBeanQuery = managedBeanQuery;
            return this;
        }
        @CustomType.Setter
        public Builder outParamDetails(@Nullable MetricExtensionQueryPropertiesOutParamDetails outParamDetails) {
            this.outParamDetails = outParamDetails;
            return this;
        }
        @CustomType.Setter
        public Builder scriptDetails(@Nullable MetricExtensionQueryPropertiesScriptDetails scriptDetails) {
            this.scriptDetails = scriptDetails;
            return this;
        }
        @CustomType.Setter
        public Builder sqlDetails(@Nullable MetricExtensionQueryPropertiesSqlDetails sqlDetails) {
            this.sqlDetails = sqlDetails;
            return this;
        }
        @CustomType.Setter
        public Builder sqlType(@Nullable String sqlType) {
            this.sqlType = sqlType;
            return this;
        }
        @CustomType.Setter
        public Builder startsWith(@Nullable String startsWith) {
            this.startsWith = startsWith;
            return this;
        }
        public MetricExtensionQueryProperties build() {
            final var o = new MetricExtensionQueryProperties();
            o.arguments = arguments;
            o.autoRowPrefix = autoRowPrefix;
            o.collectionMethod = collectionMethod;
            o.command = command;
            o.delimiter = delimiter;
            o.identityMetric = identityMetric;
            o.inParamDetails = inParamDetails;
            o.isMetricServiceEnabled = isMetricServiceEnabled;
            o.jmxAttributes = jmxAttributes;
            o.managedBeanQuery = managedBeanQuery;
            o.outParamDetails = outParamDetails;
            o.scriptDetails = scriptDetails;
            o.sqlDetails = sqlDetails;
            o.sqlType = sqlType;
            o.startsWith = startsWith;
            return o;
        }
    }
}