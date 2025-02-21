// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApmSynthetics.inputs.ConfigAvailabilityConfigurationArgs;
import com.pulumi.oci.ApmSynthetics.inputs.ConfigConfigurationArgs;
import com.pulumi.oci.ApmSynthetics.inputs.ConfigMaintenanceWindowScheduleArgs;
import com.pulumi.oci.ApmSynthetics.inputs.ConfigScriptParameterArgs;
import com.pulumi.oci.ApmSynthetics.inputs.ConfigVantagePointArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigArgs Empty = new ConfigArgs();

    /**
     * (Updatable) The APM domain ID the request is intended for.
     * 
     */
    @Import(name="apmDomainId", required=true)
    private Output<String> apmDomainId;

    /**
     * @return (Updatable) The APM domain ID the request is intended for.
     * 
     */
    public Output<String> apmDomainId() {
        return this.apmDomainId;
    }

    /**
     * (Updatable) Monitor availability configuration details.
     * 
     */
    @Import(name="availabilityConfiguration")
    private @Nullable Output<ConfigAvailabilityConfigurationArgs> availabilityConfiguration;

    /**
     * @return (Updatable) Monitor availability configuration details.
     * 
     */
    public Optional<Output<ConfigAvailabilityConfigurationArgs>> availabilityConfiguration() {
        return Optional.ofNullable(this.availabilityConfiguration);
    }

    /**
     * (Updatable) Time interval between 2 runs in round robin batch mode (*SchedulingPolicy - BATCHED_ROUND_ROBIN).
     * 
     */
    @Import(name="batchIntervalInSeconds")
    private @Nullable Output<Integer> batchIntervalInSeconds;

    /**
     * @return (Updatable) Time interval between 2 runs in round robin batch mode (*SchedulingPolicy - BATCHED_ROUND_ROBIN).
     * 
     */
    public Optional<Output<Integer>> batchIntervalInSeconds() {
        return Optional.ofNullable(this.batchIntervalInSeconds);
    }

    /**
     * (Updatable) Details of monitor configuration.
     * 
     */
    @Import(name="configuration")
    private @Nullable Output<ConfigConfigurationArgs> configuration;

    /**
     * @return (Updatable) Details of monitor configuration.
     * 
     */
    public Optional<Output<ConfigConfigurationArgs>> configuration() {
        return Optional.ofNullable(this.configuration);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Unique name that can be edited. The name should not contain any confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Unique name that can be edited. The name should not contain any confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) If enabled, domain name will resolve to an IPv6 address.
     * 
     */
    @Import(name="isIpv6")
    private @Nullable Output<Boolean> isIpv6;

    /**
     * @return (Updatable) If enabled, domain name will resolve to an IPv6 address.
     * 
     */
    public Optional<Output<Boolean>> isIpv6() {
        return Optional.ofNullable(this.isIpv6);
    }

    /**
     * (Updatable) If isRunNow is enabled, then the monitor will run immediately.
     * 
     */
    @Import(name="isRunNow")
    private @Nullable Output<Boolean> isRunNow;

    /**
     * @return (Updatable) If isRunNow is enabled, then the monitor will run immediately.
     * 
     */
    public Optional<Output<Boolean>> isRunNow() {
        return Optional.ofNullable(this.isRunNow);
    }

    /**
     * (Updatable) If runOnce is enabled, then the monitor will run once.
     * 
     */
    @Import(name="isRunOnce")
    private @Nullable Output<Boolean> isRunOnce;

    /**
     * @return (Updatable) If runOnce is enabled, then the monitor will run once.
     * 
     */
    public Optional<Output<Boolean>> isRunOnce() {
        return Optional.ofNullable(this.isRunOnce);
    }

    /**
     * (Updatable) Details required to schedule maintenance window.
     * 
     */
    @Import(name="maintenanceWindowSchedule")
    private @Nullable Output<ConfigMaintenanceWindowScheduleArgs> maintenanceWindowSchedule;

    /**
     * @return (Updatable) Details required to schedule maintenance window.
     * 
     */
    public Optional<Output<ConfigMaintenanceWindowScheduleArgs>> maintenanceWindowSchedule() {
        return Optional.ofNullable(this.maintenanceWindowSchedule);
    }

    /**
     * Type of monitor.
     * 
     */
    @Import(name="monitorType", required=true)
    private Output<String> monitorType;

    /**
     * @return Type of monitor.
     * 
     */
    public Output<String> monitorType() {
        return this.monitorType;
    }

    /**
     * (Updatable) Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds for Scripted REST, Scripted Browser and Browser monitors, and 60 seconds for REST monitor.
     * 
     */
    @Import(name="repeatIntervalInSeconds", required=true)
    private Output<Integer> repeatIntervalInSeconds;

    /**
     * @return (Updatable) Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds for Scripted REST, Scripted Browser and Browser monitors, and 60 seconds for REST monitor.
     * 
     */
    public Output<Integer> repeatIntervalInSeconds() {
        return this.repeatIntervalInSeconds;
    }

    /**
     * (Updatable) Scheduling policy to decide the distribution of monitor executions on vantage points.
     * 
     */
    @Import(name="schedulingPolicy")
    private @Nullable Output<String> schedulingPolicy;

    /**
     * @return (Updatable) Scheduling policy to decide the distribution of monitor executions on vantage points.
     * 
     */
    public Optional<Output<String>> schedulingPolicy() {
        return Optional.ofNullable(this.schedulingPolicy);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
     * 
     */
    @Import(name="scriptId")
    private @Nullable Output<String> scriptId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
     * 
     */
    public Optional<Output<String>> scriptId() {
        return Optional.ofNullable(this.scriptId);
    }

    /**
     * Name of the script.
     * 
     */
    @Import(name="scriptName")
    private @Nullable Output<String> scriptName;

    /**
     * @return Name of the script.
     * 
     */
    public Optional<Output<String>> scriptName() {
        return Optional.ofNullable(this.scriptName);
    }

    /**
     * (Updatable) List of script parameters in the monitor. This is valid only for SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;}]`
     * 
     */
    @Import(name="scriptParameters")
    private @Nullable Output<List<ConfigScriptParameterArgs>> scriptParameters;

    /**
     * @return (Updatable) List of script parameters in the monitor. This is valid only for SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;}]`
     * 
     */
    public Optional<Output<List<ConfigScriptParameterArgs>>> scriptParameters() {
        return Optional.ofNullable(this.scriptParameters);
    }

    /**
     * (Updatable) Enables or disables the monitor.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return (Updatable) Enables or disables the monitor.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * (Updatable) Specify the endpoint on which to run the monitor. For BROWSER, REST, NETWORK, DNS and FTP monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is. For NETWORK monitor with TCP protocol, a port needs to be provided along with target. Example: 192.168.0.1:80.
     * 
     */
    @Import(name="target")
    private @Nullable Output<String> target;

    /**
     * @return (Updatable) Specify the endpoint on which to run the monitor. For BROWSER, REST, NETWORK, DNS and FTP monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is. For NETWORK monitor with TCP protocol, a port needs to be provided along with target. Example: 192.168.0.1:80.
     * 
     */
    public Optional<Output<String>> target() {
        return Optional.ofNullable(this.target);
    }

    /**
     * (Updatable) Timeout in seconds. If isFailureRetried is true, then timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. If isFailureRetried is false, then timeout cannot be more than 50% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60 for Scripted REST, Scripted Browser and Browser monitors. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
     * 
     */
    @Import(name="timeoutInSeconds")
    private @Nullable Output<Integer> timeoutInSeconds;

    /**
     * @return (Updatable) Timeout in seconds. If isFailureRetried is true, then timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. If isFailureRetried is false, then timeout cannot be more than 50% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60 for Scripted REST, Scripted Browser and Browser monitors. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
     * 
     */
    public Optional<Output<Integer>> timeoutInSeconds() {
        return Optional.ofNullable(this.timeoutInSeconds);
    }

    /**
     * (Updatable) A list of public and dedicated vantage points from which to execute the monitor. Use /publicVantagePoints to fetch public vantage points, and /dedicatedVantagePoints to fetch dedicated vantage points.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="vantagePoints", required=true)
    private Output<List<ConfigVantagePointArgs>> vantagePoints;

    /**
     * @return (Updatable) A list of public and dedicated vantage points from which to execute the monitor. Use /publicVantagePoints to fetch public vantage points, and /dedicatedVantagePoints to fetch dedicated vantage points.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<List<ConfigVantagePointArgs>> vantagePoints() {
        return this.vantagePoints;
    }

    private ConfigArgs() {}

    private ConfigArgs(ConfigArgs $) {
        this.apmDomainId = $.apmDomainId;
        this.availabilityConfiguration = $.availabilityConfiguration;
        this.batchIntervalInSeconds = $.batchIntervalInSeconds;
        this.configuration = $.configuration;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isIpv6 = $.isIpv6;
        this.isRunNow = $.isRunNow;
        this.isRunOnce = $.isRunOnce;
        this.maintenanceWindowSchedule = $.maintenanceWindowSchedule;
        this.monitorType = $.monitorType;
        this.repeatIntervalInSeconds = $.repeatIntervalInSeconds;
        this.schedulingPolicy = $.schedulingPolicy;
        this.scriptId = $.scriptId;
        this.scriptName = $.scriptName;
        this.scriptParameters = $.scriptParameters;
        this.status = $.status;
        this.target = $.target;
        this.timeoutInSeconds = $.timeoutInSeconds;
        this.vantagePoints = $.vantagePoints;
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
         * @param apmDomainId (Updatable) The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(Output<String> apmDomainId) {
            $.apmDomainId = apmDomainId;
            return this;
        }

        /**
         * @param apmDomainId (Updatable) The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(String apmDomainId) {
            return apmDomainId(Output.of(apmDomainId));
        }

        /**
         * @param availabilityConfiguration (Updatable) Monitor availability configuration details.
         * 
         * @return builder
         * 
         */
        public Builder availabilityConfiguration(@Nullable Output<ConfigAvailabilityConfigurationArgs> availabilityConfiguration) {
            $.availabilityConfiguration = availabilityConfiguration;
            return this;
        }

        /**
         * @param availabilityConfiguration (Updatable) Monitor availability configuration details.
         * 
         * @return builder
         * 
         */
        public Builder availabilityConfiguration(ConfigAvailabilityConfigurationArgs availabilityConfiguration) {
            return availabilityConfiguration(Output.of(availabilityConfiguration));
        }

        /**
         * @param batchIntervalInSeconds (Updatable) Time interval between 2 runs in round robin batch mode (*SchedulingPolicy - BATCHED_ROUND_ROBIN).
         * 
         * @return builder
         * 
         */
        public Builder batchIntervalInSeconds(@Nullable Output<Integer> batchIntervalInSeconds) {
            $.batchIntervalInSeconds = batchIntervalInSeconds;
            return this;
        }

        /**
         * @param batchIntervalInSeconds (Updatable) Time interval between 2 runs in round robin batch mode (*SchedulingPolicy - BATCHED_ROUND_ROBIN).
         * 
         * @return builder
         * 
         */
        public Builder batchIntervalInSeconds(Integer batchIntervalInSeconds) {
            return batchIntervalInSeconds(Output.of(batchIntervalInSeconds));
        }

        /**
         * @param configuration (Updatable) Details of monitor configuration.
         * 
         * @return builder
         * 
         */
        public Builder configuration(@Nullable Output<ConfigConfigurationArgs> configuration) {
            $.configuration = configuration;
            return this;
        }

        /**
         * @param configuration (Updatable) Details of monitor configuration.
         * 
         * @return builder
         * 
         */
        public Builder configuration(ConfigConfigurationArgs configuration) {
            return configuration(Output.of(configuration));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Unique name that can be edited. The name should not contain any confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Unique name that can be edited. The name should not contain any confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isIpv6 (Updatable) If enabled, domain name will resolve to an IPv6 address.
         * 
         * @return builder
         * 
         */
        public Builder isIpv6(@Nullable Output<Boolean> isIpv6) {
            $.isIpv6 = isIpv6;
            return this;
        }

        /**
         * @param isIpv6 (Updatable) If enabled, domain name will resolve to an IPv6 address.
         * 
         * @return builder
         * 
         */
        public Builder isIpv6(Boolean isIpv6) {
            return isIpv6(Output.of(isIpv6));
        }

        /**
         * @param isRunNow (Updatable) If isRunNow is enabled, then the monitor will run immediately.
         * 
         * @return builder
         * 
         */
        public Builder isRunNow(@Nullable Output<Boolean> isRunNow) {
            $.isRunNow = isRunNow;
            return this;
        }

        /**
         * @param isRunNow (Updatable) If isRunNow is enabled, then the monitor will run immediately.
         * 
         * @return builder
         * 
         */
        public Builder isRunNow(Boolean isRunNow) {
            return isRunNow(Output.of(isRunNow));
        }

        /**
         * @param isRunOnce (Updatable) If runOnce is enabled, then the monitor will run once.
         * 
         * @return builder
         * 
         */
        public Builder isRunOnce(@Nullable Output<Boolean> isRunOnce) {
            $.isRunOnce = isRunOnce;
            return this;
        }

        /**
         * @param isRunOnce (Updatable) If runOnce is enabled, then the monitor will run once.
         * 
         * @return builder
         * 
         */
        public Builder isRunOnce(Boolean isRunOnce) {
            return isRunOnce(Output.of(isRunOnce));
        }

        /**
         * @param maintenanceWindowSchedule (Updatable) Details required to schedule maintenance window.
         * 
         * @return builder
         * 
         */
        public Builder maintenanceWindowSchedule(@Nullable Output<ConfigMaintenanceWindowScheduleArgs> maintenanceWindowSchedule) {
            $.maintenanceWindowSchedule = maintenanceWindowSchedule;
            return this;
        }

        /**
         * @param maintenanceWindowSchedule (Updatable) Details required to schedule maintenance window.
         * 
         * @return builder
         * 
         */
        public Builder maintenanceWindowSchedule(ConfigMaintenanceWindowScheduleArgs maintenanceWindowSchedule) {
            return maintenanceWindowSchedule(Output.of(maintenanceWindowSchedule));
        }

        /**
         * @param monitorType Type of monitor.
         * 
         * @return builder
         * 
         */
        public Builder monitorType(Output<String> monitorType) {
            $.monitorType = monitorType;
            return this;
        }

        /**
         * @param monitorType Type of monitor.
         * 
         * @return builder
         * 
         */
        public Builder monitorType(String monitorType) {
            return monitorType(Output.of(monitorType));
        }

        /**
         * @param repeatIntervalInSeconds (Updatable) Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds for Scripted REST, Scripted Browser and Browser monitors, and 60 seconds for REST monitor.
         * 
         * @return builder
         * 
         */
        public Builder repeatIntervalInSeconds(Output<Integer> repeatIntervalInSeconds) {
            $.repeatIntervalInSeconds = repeatIntervalInSeconds;
            return this;
        }

        /**
         * @param repeatIntervalInSeconds (Updatable) Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds for Scripted REST, Scripted Browser and Browser monitors, and 60 seconds for REST monitor.
         * 
         * @return builder
         * 
         */
        public Builder repeatIntervalInSeconds(Integer repeatIntervalInSeconds) {
            return repeatIntervalInSeconds(Output.of(repeatIntervalInSeconds));
        }

        /**
         * @param schedulingPolicy (Updatable) Scheduling policy to decide the distribution of monitor executions on vantage points.
         * 
         * @return builder
         * 
         */
        public Builder schedulingPolicy(@Nullable Output<String> schedulingPolicy) {
            $.schedulingPolicy = schedulingPolicy;
            return this;
        }

        /**
         * @param schedulingPolicy (Updatable) Scheduling policy to decide the distribution of monitor executions on vantage points.
         * 
         * @return builder
         * 
         */
        public Builder schedulingPolicy(String schedulingPolicy) {
            return schedulingPolicy(Output.of(schedulingPolicy));
        }

        /**
         * @param scriptId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
         * 
         * @return builder
         * 
         */
        public Builder scriptId(@Nullable Output<String> scriptId) {
            $.scriptId = scriptId;
            return this;
        }

        /**
         * @param scriptId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
         * 
         * @return builder
         * 
         */
        public Builder scriptId(String scriptId) {
            return scriptId(Output.of(scriptId));
        }

        /**
         * @param scriptName Name of the script.
         * 
         * @return builder
         * 
         */
        public Builder scriptName(@Nullable Output<String> scriptName) {
            $.scriptName = scriptName;
            return this;
        }

        /**
         * @param scriptName Name of the script.
         * 
         * @return builder
         * 
         */
        public Builder scriptName(String scriptName) {
            return scriptName(Output.of(scriptName));
        }

        /**
         * @param scriptParameters (Updatable) List of script parameters in the monitor. This is valid only for SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;}]`
         * 
         * @return builder
         * 
         */
        public Builder scriptParameters(@Nullable Output<List<ConfigScriptParameterArgs>> scriptParameters) {
            $.scriptParameters = scriptParameters;
            return this;
        }

        /**
         * @param scriptParameters (Updatable) List of script parameters in the monitor. This is valid only for SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;}]`
         * 
         * @return builder
         * 
         */
        public Builder scriptParameters(List<ConfigScriptParameterArgs> scriptParameters) {
            return scriptParameters(Output.of(scriptParameters));
        }

        /**
         * @param scriptParameters (Updatable) List of script parameters in the monitor. This is valid only for SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;}]`
         * 
         * @return builder
         * 
         */
        public Builder scriptParameters(ConfigScriptParameterArgs... scriptParameters) {
            return scriptParameters(List.of(scriptParameters));
        }

        /**
         * @param status (Updatable) Enables or disables the monitor.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status (Updatable) Enables or disables the monitor.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param target (Updatable) Specify the endpoint on which to run the monitor. For BROWSER, REST, NETWORK, DNS and FTP monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is. For NETWORK monitor with TCP protocol, a port needs to be provided along with target. Example: 192.168.0.1:80.
         * 
         * @return builder
         * 
         */
        public Builder target(@Nullable Output<String> target) {
            $.target = target;
            return this;
        }

        /**
         * @param target (Updatable) Specify the endpoint on which to run the monitor. For BROWSER, REST, NETWORK, DNS and FTP monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is. For NETWORK monitor with TCP protocol, a port needs to be provided along with target. Example: 192.168.0.1:80.
         * 
         * @return builder
         * 
         */
        public Builder target(String target) {
            return target(Output.of(target));
        }

        /**
         * @param timeoutInSeconds (Updatable) Timeout in seconds. If isFailureRetried is true, then timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. If isFailureRetried is false, then timeout cannot be more than 50% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60 for Scripted REST, Scripted Browser and Browser monitors. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
         * 
         * @return builder
         * 
         */
        public Builder timeoutInSeconds(@Nullable Output<Integer> timeoutInSeconds) {
            $.timeoutInSeconds = timeoutInSeconds;
            return this;
        }

        /**
         * @param timeoutInSeconds (Updatable) Timeout in seconds. If isFailureRetried is true, then timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. If isFailureRetried is false, then timeout cannot be more than 50% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60 for Scripted REST, Scripted Browser and Browser monitors. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
         * 
         * @return builder
         * 
         */
        public Builder timeoutInSeconds(Integer timeoutInSeconds) {
            return timeoutInSeconds(Output.of(timeoutInSeconds));
        }

        /**
         * @param vantagePoints (Updatable) A list of public and dedicated vantage points from which to execute the monitor. Use /publicVantagePoints to fetch public vantage points, and /dedicatedVantagePoints to fetch dedicated vantage points.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vantagePoints(Output<List<ConfigVantagePointArgs>> vantagePoints) {
            $.vantagePoints = vantagePoints;
            return this;
        }

        /**
         * @param vantagePoints (Updatable) A list of public and dedicated vantage points from which to execute the monitor. Use /publicVantagePoints to fetch public vantage points, and /dedicatedVantagePoints to fetch dedicated vantage points.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vantagePoints(List<ConfigVantagePointArgs> vantagePoints) {
            return vantagePoints(Output.of(vantagePoints));
        }

        /**
         * @param vantagePoints (Updatable) A list of public and dedicated vantage points from which to execute the monitor. Use /publicVantagePoints to fetch public vantage points, and /dedicatedVantagePoints to fetch dedicated vantage points.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder vantagePoints(ConfigVantagePointArgs... vantagePoints) {
            return vantagePoints(List.of(vantagePoints));
        }

        public ConfigArgs build() {
            if ($.apmDomainId == null) {
                throw new MissingRequiredPropertyException("ConfigArgs", "apmDomainId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("ConfigArgs", "displayName");
            }
            if ($.monitorType == null) {
                throw new MissingRequiredPropertyException("ConfigArgs", "monitorType");
            }
            if ($.repeatIntervalInSeconds == null) {
                throw new MissingRequiredPropertyException("ConfigArgs", "repeatIntervalInSeconds");
            }
            if ($.vantagePoints == null) {
                throw new MissingRequiredPropertyException("ConfigArgs", "vantagePoints");
            }
            return $;
        }
    }

}
