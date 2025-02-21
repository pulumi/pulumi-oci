// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.inputs.MetricExtensionQueryPropertiesInParamDetailArgs;
import com.pulumi.oci.StackMonitoring.inputs.MetricExtensionQueryPropertiesOutParamDetailsArgs;
import com.pulumi.oci.StackMonitoring.inputs.MetricExtensionQueryPropertiesScriptDetailsArgs;
import com.pulumi.oci.StackMonitoring.inputs.MetricExtensionQueryPropertiesSqlDetailsArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MetricExtensionQueryPropertiesArgs extends com.pulumi.resources.ResourceArgs {

    public static final MetricExtensionQueryPropertiesArgs Empty = new MetricExtensionQueryPropertiesArgs();

    /**
     * (Updatable) Arguments required by either command or script
     * 
     */
    @Import(name="arguments")
    private @Nullable Output<String> arguments;

    /**
     * @return (Updatable) Arguments required by either command or script
     * 
     */
    public Optional<Output<String>> arguments() {
        return Optional.ofNullable(this.arguments);
    }

    /**
     * (Updatable) Prefix for an auto generated metric, in case multiple rows with non unique key values are returned
     * 
     */
    @Import(name="autoRowPrefix")
    private @Nullable Output<String> autoRowPrefix;

    /**
     * @return (Updatable) Prefix for an auto generated metric, in case multiple rows with non unique key values are returned
     * 
     */
    public Optional<Output<String>> autoRowPrefix() {
        return Optional.ofNullable(this.autoRowPrefix);
    }

    /**
     * (Updatable) Type of possible collection methods.
     * 
     */
    @Import(name="collectionMethod", required=true)
    private Output<String> collectionMethod;

    /**
     * @return (Updatable) Type of possible collection methods.
     * 
     */
    public Output<String> collectionMethod() {
        return this.collectionMethod;
    }

    /**
     * (Updatable) OS command to execute without arguments
     * 
     */
    @Import(name="command")
    private @Nullable Output<String> command;

    /**
     * @return (Updatable) OS command to execute without arguments
     * 
     */
    public Optional<Output<String>> command() {
        return Optional.ofNullable(this.command);
    }

    /**
     * (Updatable) Character used to delimit multiple metric values in single line of output
     * 
     */
    @Import(name="delimiter")
    private @Nullable Output<String> delimiter;

    /**
     * @return (Updatable) Character used to delimit multiple metric values in single line of output
     * 
     */
    public Optional<Output<String>> delimiter() {
        return Optional.ofNullable(this.delimiter);
    }

    /**
     * (Updatable) Semi-colon separated list of key properties from Managed Bean ObjectName to be used as key metrics
     * 
     */
    @Import(name="identityMetric")
    private @Nullable Output<String> identityMetric;

    /**
     * @return (Updatable) Semi-colon separated list of key properties from Managed Bean ObjectName to be used as key metrics
     * 
     */
    public Optional<Output<String>> identityMetric() {
        return Optional.ofNullable(this.identityMetric);
    }

    /**
     * (Updatable) List of values and position of PL/SQL procedure IN parameters
     * 
     */
    @Import(name="inParamDetails")
    private @Nullable Output<List<MetricExtensionQueryPropertiesInParamDetailArgs>> inParamDetails;

    /**
     * @return (Updatable) List of values and position of PL/SQL procedure IN parameters
     * 
     */
    public Optional<Output<List<MetricExtensionQueryPropertiesInParamDetailArgs>>> inParamDetails() {
        return Optional.ofNullable(this.inParamDetails);
    }

    /**
     * (Updatable) Indicates if Metric Service is enabled on server domain
     * 
     */
    @Import(name="isMetricServiceEnabled")
    private @Nullable Output<Boolean> isMetricServiceEnabled;

    /**
     * @return (Updatable) Indicates if Metric Service is enabled on server domain
     * 
     */
    public Optional<Output<Boolean>> isMetricServiceEnabled() {
        return Optional.ofNullable(this.isMetricServiceEnabled);
    }

    /**
     * (Updatable) List of JMX attributes or Metric Service Table columns separated by semi-colon
     * 
     */
    @Import(name="jmxAttributes")
    private @Nullable Output<String> jmxAttributes;

    /**
     * @return (Updatable) List of JMX attributes or Metric Service Table columns separated by semi-colon
     * 
     */
    public Optional<Output<String>> jmxAttributes() {
        return Optional.ofNullable(this.jmxAttributes);
    }

    /**
     * (Updatable) JMX Managed Bean Query or Metric Service Table name
     * 
     */
    @Import(name="managedBeanQuery")
    private @Nullable Output<String> managedBeanQuery;

    /**
     * @return (Updatable) JMX Managed Bean Query or Metric Service Table name
     * 
     */
    public Optional<Output<String>> managedBeanQuery() {
        return Optional.ofNullable(this.managedBeanQuery);
    }

    /**
     * (Updatable) Position and SQL Type of PL/SQL OUT parameter
     * 
     */
    @Import(name="outParamDetails")
    private @Nullable Output<MetricExtensionQueryPropertiesOutParamDetailsArgs> outParamDetails;

    /**
     * @return (Updatable) Position and SQL Type of PL/SQL OUT parameter
     * 
     */
    public Optional<Output<MetricExtensionQueryPropertiesOutParamDetailsArgs>> outParamDetails() {
        return Optional.ofNullable(this.outParamDetails);
    }

    /**
     * (Updatable) Supported protocol of resources to be associated with this metric extension. This is optional and defaults to HTTPS, which uses secure connection to the URL
     * 
     */
    @Import(name="protocolType")
    private @Nullable Output<String> protocolType;

    /**
     * @return (Updatable) Supported protocol of resources to be associated with this metric extension. This is optional and defaults to HTTPS, which uses secure connection to the URL
     * 
     */
    public Optional<Output<String>> protocolType() {
        return Optional.ofNullable(this.protocolType);
    }

    /**
     * (Updatable) Type of content response given by the http(s) URL
     * 
     */
    @Import(name="responseContentType")
    private @Nullable Output<String> responseContentType;

    /**
     * @return (Updatable) Type of content response given by the http(s) URL
     * 
     */
    public Optional<Output<String>> responseContentType() {
        return Optional.ofNullable(this.responseContentType);
    }

    /**
     * (Updatable) Script details applicable to any OS Command/HTTP based Metric Extension which needs to run a script to collect data. For removing it during OS Command based Metric Extension update, set its &#34;content&#34; property to an empty string. In that case, &#34;name&#34; property value is ignored.
     * 
     */
    @Import(name="scriptDetails")
    private @Nullable Output<MetricExtensionQueryPropertiesScriptDetailsArgs> scriptDetails;

    /**
     * @return (Updatable) Script details applicable to any OS Command/HTTP based Metric Extension which needs to run a script to collect data. For removing it during OS Command based Metric Extension update, set its &#34;content&#34; property to an empty string. In that case, &#34;name&#34; property value is ignored.
     * 
     */
    public Optional<Output<MetricExtensionQueryPropertiesScriptDetailsArgs>> scriptDetails() {
        return Optional.ofNullable(this.scriptDetails);
    }

    /**
     * (Updatable) Details of Sql content which needs to execute to collect Metric Extension data
     * 
     */
    @Import(name="sqlDetails")
    private @Nullable Output<MetricExtensionQueryPropertiesSqlDetailsArgs> sqlDetails;

    /**
     * @return (Updatable) Details of Sql content which needs to execute to collect Metric Extension data
     * 
     */
    public Optional<Output<MetricExtensionQueryPropertiesSqlDetailsArgs>> sqlDetails() {
        return Optional.ofNullable(this.sqlDetails);
    }

    /**
     * (Updatable) Type of SQL data collection method i.e. either a Statement or SQL Script File
     * 
     */
    @Import(name="sqlType")
    private @Nullable Output<String> sqlType;

    /**
     * @return (Updatable) Type of SQL data collection method i.e. either a Statement or SQL Script File
     * 
     */
    public Optional<Output<String>> sqlType() {
        return Optional.ofNullable(this.sqlType);
    }

    /**
     * (Updatable) String prefix used to identify metric output of the OS Command
     * 
     */
    @Import(name="startsWith")
    private @Nullable Output<String> startsWith;

    /**
     * @return (Updatable) String prefix used to identify metric output of the OS Command
     * 
     */
    public Optional<Output<String>> startsWith() {
        return Optional.ofNullable(this.startsWith);
    }

    /**
     * (Updatable) Http(s) end point URL
     * 
     */
    @Import(name="url")
    private @Nullable Output<String> url;

    /**
     * @return (Updatable) Http(s) end point URL
     * 
     */
    public Optional<Output<String>> url() {
        return Optional.ofNullable(this.url);
    }

    private MetricExtensionQueryPropertiesArgs() {}

    private MetricExtensionQueryPropertiesArgs(MetricExtensionQueryPropertiesArgs $) {
        this.arguments = $.arguments;
        this.autoRowPrefix = $.autoRowPrefix;
        this.collectionMethod = $.collectionMethod;
        this.command = $.command;
        this.delimiter = $.delimiter;
        this.identityMetric = $.identityMetric;
        this.inParamDetails = $.inParamDetails;
        this.isMetricServiceEnabled = $.isMetricServiceEnabled;
        this.jmxAttributes = $.jmxAttributes;
        this.managedBeanQuery = $.managedBeanQuery;
        this.outParamDetails = $.outParamDetails;
        this.protocolType = $.protocolType;
        this.responseContentType = $.responseContentType;
        this.scriptDetails = $.scriptDetails;
        this.sqlDetails = $.sqlDetails;
        this.sqlType = $.sqlType;
        this.startsWith = $.startsWith;
        this.url = $.url;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MetricExtensionQueryPropertiesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MetricExtensionQueryPropertiesArgs $;

        public Builder() {
            $ = new MetricExtensionQueryPropertiesArgs();
        }

        public Builder(MetricExtensionQueryPropertiesArgs defaults) {
            $ = new MetricExtensionQueryPropertiesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param arguments (Updatable) Arguments required by either command or script
         * 
         * @return builder
         * 
         */
        public Builder arguments(@Nullable Output<String> arguments) {
            $.arguments = arguments;
            return this;
        }

        /**
         * @param arguments (Updatable) Arguments required by either command or script
         * 
         * @return builder
         * 
         */
        public Builder arguments(String arguments) {
            return arguments(Output.of(arguments));
        }

        /**
         * @param autoRowPrefix (Updatable) Prefix for an auto generated metric, in case multiple rows with non unique key values are returned
         * 
         * @return builder
         * 
         */
        public Builder autoRowPrefix(@Nullable Output<String> autoRowPrefix) {
            $.autoRowPrefix = autoRowPrefix;
            return this;
        }

        /**
         * @param autoRowPrefix (Updatable) Prefix for an auto generated metric, in case multiple rows with non unique key values are returned
         * 
         * @return builder
         * 
         */
        public Builder autoRowPrefix(String autoRowPrefix) {
            return autoRowPrefix(Output.of(autoRowPrefix));
        }

        /**
         * @param collectionMethod (Updatable) Type of possible collection methods.
         * 
         * @return builder
         * 
         */
        public Builder collectionMethod(Output<String> collectionMethod) {
            $.collectionMethod = collectionMethod;
            return this;
        }

        /**
         * @param collectionMethod (Updatable) Type of possible collection methods.
         * 
         * @return builder
         * 
         */
        public Builder collectionMethod(String collectionMethod) {
            return collectionMethod(Output.of(collectionMethod));
        }

        /**
         * @param command (Updatable) OS command to execute without arguments
         * 
         * @return builder
         * 
         */
        public Builder command(@Nullable Output<String> command) {
            $.command = command;
            return this;
        }

        /**
         * @param command (Updatable) OS command to execute without arguments
         * 
         * @return builder
         * 
         */
        public Builder command(String command) {
            return command(Output.of(command));
        }

        /**
         * @param delimiter (Updatable) Character used to delimit multiple metric values in single line of output
         * 
         * @return builder
         * 
         */
        public Builder delimiter(@Nullable Output<String> delimiter) {
            $.delimiter = delimiter;
            return this;
        }

        /**
         * @param delimiter (Updatable) Character used to delimit multiple metric values in single line of output
         * 
         * @return builder
         * 
         */
        public Builder delimiter(String delimiter) {
            return delimiter(Output.of(delimiter));
        }

        /**
         * @param identityMetric (Updatable) Semi-colon separated list of key properties from Managed Bean ObjectName to be used as key metrics
         * 
         * @return builder
         * 
         */
        public Builder identityMetric(@Nullable Output<String> identityMetric) {
            $.identityMetric = identityMetric;
            return this;
        }

        /**
         * @param identityMetric (Updatable) Semi-colon separated list of key properties from Managed Bean ObjectName to be used as key metrics
         * 
         * @return builder
         * 
         */
        public Builder identityMetric(String identityMetric) {
            return identityMetric(Output.of(identityMetric));
        }

        /**
         * @param inParamDetails (Updatable) List of values and position of PL/SQL procedure IN parameters
         * 
         * @return builder
         * 
         */
        public Builder inParamDetails(@Nullable Output<List<MetricExtensionQueryPropertiesInParamDetailArgs>> inParamDetails) {
            $.inParamDetails = inParamDetails;
            return this;
        }

        /**
         * @param inParamDetails (Updatable) List of values and position of PL/SQL procedure IN parameters
         * 
         * @return builder
         * 
         */
        public Builder inParamDetails(List<MetricExtensionQueryPropertiesInParamDetailArgs> inParamDetails) {
            return inParamDetails(Output.of(inParamDetails));
        }

        /**
         * @param inParamDetails (Updatable) List of values and position of PL/SQL procedure IN parameters
         * 
         * @return builder
         * 
         */
        public Builder inParamDetails(MetricExtensionQueryPropertiesInParamDetailArgs... inParamDetails) {
            return inParamDetails(List.of(inParamDetails));
        }

        /**
         * @param isMetricServiceEnabled (Updatable) Indicates if Metric Service is enabled on server domain
         * 
         * @return builder
         * 
         */
        public Builder isMetricServiceEnabled(@Nullable Output<Boolean> isMetricServiceEnabled) {
            $.isMetricServiceEnabled = isMetricServiceEnabled;
            return this;
        }

        /**
         * @param isMetricServiceEnabled (Updatable) Indicates if Metric Service is enabled on server domain
         * 
         * @return builder
         * 
         */
        public Builder isMetricServiceEnabled(Boolean isMetricServiceEnabled) {
            return isMetricServiceEnabled(Output.of(isMetricServiceEnabled));
        }

        /**
         * @param jmxAttributes (Updatable) List of JMX attributes or Metric Service Table columns separated by semi-colon
         * 
         * @return builder
         * 
         */
        public Builder jmxAttributes(@Nullable Output<String> jmxAttributes) {
            $.jmxAttributes = jmxAttributes;
            return this;
        }

        /**
         * @param jmxAttributes (Updatable) List of JMX attributes or Metric Service Table columns separated by semi-colon
         * 
         * @return builder
         * 
         */
        public Builder jmxAttributes(String jmxAttributes) {
            return jmxAttributes(Output.of(jmxAttributes));
        }

        /**
         * @param managedBeanQuery (Updatable) JMX Managed Bean Query or Metric Service Table name
         * 
         * @return builder
         * 
         */
        public Builder managedBeanQuery(@Nullable Output<String> managedBeanQuery) {
            $.managedBeanQuery = managedBeanQuery;
            return this;
        }

        /**
         * @param managedBeanQuery (Updatable) JMX Managed Bean Query or Metric Service Table name
         * 
         * @return builder
         * 
         */
        public Builder managedBeanQuery(String managedBeanQuery) {
            return managedBeanQuery(Output.of(managedBeanQuery));
        }

        /**
         * @param outParamDetails (Updatable) Position and SQL Type of PL/SQL OUT parameter
         * 
         * @return builder
         * 
         */
        public Builder outParamDetails(@Nullable Output<MetricExtensionQueryPropertiesOutParamDetailsArgs> outParamDetails) {
            $.outParamDetails = outParamDetails;
            return this;
        }

        /**
         * @param outParamDetails (Updatable) Position and SQL Type of PL/SQL OUT parameter
         * 
         * @return builder
         * 
         */
        public Builder outParamDetails(MetricExtensionQueryPropertiesOutParamDetailsArgs outParamDetails) {
            return outParamDetails(Output.of(outParamDetails));
        }

        /**
         * @param protocolType (Updatable) Supported protocol of resources to be associated with this metric extension. This is optional and defaults to HTTPS, which uses secure connection to the URL
         * 
         * @return builder
         * 
         */
        public Builder protocolType(@Nullable Output<String> protocolType) {
            $.protocolType = protocolType;
            return this;
        }

        /**
         * @param protocolType (Updatable) Supported protocol of resources to be associated with this metric extension. This is optional and defaults to HTTPS, which uses secure connection to the URL
         * 
         * @return builder
         * 
         */
        public Builder protocolType(String protocolType) {
            return protocolType(Output.of(protocolType));
        }

        /**
         * @param responseContentType (Updatable) Type of content response given by the http(s) URL
         * 
         * @return builder
         * 
         */
        public Builder responseContentType(@Nullable Output<String> responseContentType) {
            $.responseContentType = responseContentType;
            return this;
        }

        /**
         * @param responseContentType (Updatable) Type of content response given by the http(s) URL
         * 
         * @return builder
         * 
         */
        public Builder responseContentType(String responseContentType) {
            return responseContentType(Output.of(responseContentType));
        }

        /**
         * @param scriptDetails (Updatable) Script details applicable to any OS Command/HTTP based Metric Extension which needs to run a script to collect data. For removing it during OS Command based Metric Extension update, set its &#34;content&#34; property to an empty string. In that case, &#34;name&#34; property value is ignored.
         * 
         * @return builder
         * 
         */
        public Builder scriptDetails(@Nullable Output<MetricExtensionQueryPropertiesScriptDetailsArgs> scriptDetails) {
            $.scriptDetails = scriptDetails;
            return this;
        }

        /**
         * @param scriptDetails (Updatable) Script details applicable to any OS Command/HTTP based Metric Extension which needs to run a script to collect data. For removing it during OS Command based Metric Extension update, set its &#34;content&#34; property to an empty string. In that case, &#34;name&#34; property value is ignored.
         * 
         * @return builder
         * 
         */
        public Builder scriptDetails(MetricExtensionQueryPropertiesScriptDetailsArgs scriptDetails) {
            return scriptDetails(Output.of(scriptDetails));
        }

        /**
         * @param sqlDetails (Updatable) Details of Sql content which needs to execute to collect Metric Extension data
         * 
         * @return builder
         * 
         */
        public Builder sqlDetails(@Nullable Output<MetricExtensionQueryPropertiesSqlDetailsArgs> sqlDetails) {
            $.sqlDetails = sqlDetails;
            return this;
        }

        /**
         * @param sqlDetails (Updatable) Details of Sql content which needs to execute to collect Metric Extension data
         * 
         * @return builder
         * 
         */
        public Builder sqlDetails(MetricExtensionQueryPropertiesSqlDetailsArgs sqlDetails) {
            return sqlDetails(Output.of(sqlDetails));
        }

        /**
         * @param sqlType (Updatable) Type of SQL data collection method i.e. either a Statement or SQL Script File
         * 
         * @return builder
         * 
         */
        public Builder sqlType(@Nullable Output<String> sqlType) {
            $.sqlType = sqlType;
            return this;
        }

        /**
         * @param sqlType (Updatable) Type of SQL data collection method i.e. either a Statement or SQL Script File
         * 
         * @return builder
         * 
         */
        public Builder sqlType(String sqlType) {
            return sqlType(Output.of(sqlType));
        }

        /**
         * @param startsWith (Updatable) String prefix used to identify metric output of the OS Command
         * 
         * @return builder
         * 
         */
        public Builder startsWith(@Nullable Output<String> startsWith) {
            $.startsWith = startsWith;
            return this;
        }

        /**
         * @param startsWith (Updatable) String prefix used to identify metric output of the OS Command
         * 
         * @return builder
         * 
         */
        public Builder startsWith(String startsWith) {
            return startsWith(Output.of(startsWith));
        }

        /**
         * @param url (Updatable) Http(s) end point URL
         * 
         * @return builder
         * 
         */
        public Builder url(@Nullable Output<String> url) {
            $.url = url;
            return this;
        }

        /**
         * @param url (Updatable) Http(s) end point URL
         * 
         * @return builder
         * 
         */
        public Builder url(String url) {
            return url(Output.of(url));
        }

        public MetricExtensionQueryPropertiesArgs build() {
            if ($.collectionMethod == null) {
                throw new MissingRequiredPropertyException("MetricExtensionQueryPropertiesArgs", "collectionMethod");
            }
            return $;
        }
    }

}
