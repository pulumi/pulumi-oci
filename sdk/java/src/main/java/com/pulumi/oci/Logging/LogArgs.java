// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Logging.inputs.LogConfigurationArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class LogArgs extends com.pulumi.resources.ResourceArgs {

    public static final LogArgs Empty = new LogArgs();

    /**
     * Log object configuration.
     * 
     */
    @Import(name="configuration")
    private @Nullable Output<LogConfigurationArgs> configuration;

    /**
     * @return Log object configuration.
     * 
     */
    public Optional<Output<LogConfigurationArgs>> configuration() {
        return Optional.ofNullable(this.configuration);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Whether or not this resource is currently enabled.
     * 
     */
    @Import(name="isEnabled")
    private @Nullable Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Whether or not this resource is currently enabled.
     * 
     */
    public Optional<Output<Boolean>> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    /**
     * (Updatable) OCID of a log group to work with.
     * 
     */
    @Import(name="logGroupId", required=true)
    private Output<String> logGroupId;

    /**
     * @return (Updatable) OCID of a log group to work with.
     * 
     */
    public Output<String> logGroupId() {
        return this.logGroupId;
    }

    /**
     * The logType that the log object is for, whether custom or service.
     * 
     */
    @Import(name="logType", required=true)
    private Output<String> logType;

    /**
     * @return The logType that the log object is for, whether custom or service.
     * 
     */
    public Output<String> logType() {
        return this.logType;
    }

    /**
     * (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on until 180).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="retentionDuration")
    private @Nullable Output<Integer> retentionDuration;

    /**
     * @return (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on until 180).
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Integer>> retentionDuration() {
        return Optional.ofNullable(this.retentionDuration);
    }

    private LogArgs() {}

    private LogArgs(LogArgs $) {
        this.configuration = $.configuration;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isEnabled = $.isEnabled;
        this.logGroupId = $.logGroupId;
        this.logType = $.logType;
        this.retentionDuration = $.retentionDuration;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(LogArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private LogArgs $;

        public Builder() {
            $ = new LogArgs();
        }

        public Builder(LogArgs defaults) {
            $ = new LogArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configuration Log object configuration.
         * 
         * @return builder
         * 
         */
        public Builder configuration(@Nullable Output<LogConfigurationArgs> configuration) {
            $.configuration = configuration;
            return this;
        }

        /**
         * @param configuration Log object configuration.
         * 
         * @return builder
         * 
         */
        public Builder configuration(LogConfigurationArgs configuration) {
            return configuration(Output.of(configuration));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isEnabled (Updatable) Whether or not this resource is currently enabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(@Nullable Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Whether or not this resource is currently enabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param logGroupId (Updatable) OCID of a log group to work with.
         * 
         * @return builder
         * 
         */
        public Builder logGroupId(Output<String> logGroupId) {
            $.logGroupId = logGroupId;
            return this;
        }

        /**
         * @param logGroupId (Updatable) OCID of a log group to work with.
         * 
         * @return builder
         * 
         */
        public Builder logGroupId(String logGroupId) {
            return logGroupId(Output.of(logGroupId));
        }

        /**
         * @param logType The logType that the log object is for, whether custom or service.
         * 
         * @return builder
         * 
         */
        public Builder logType(Output<String> logType) {
            $.logType = logType;
            return this;
        }

        /**
         * @param logType The logType that the log object is for, whether custom or service.
         * 
         * @return builder
         * 
         */
        public Builder logType(String logType) {
            return logType(Output.of(logType));
        }

        /**
         * @param retentionDuration (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on until 180).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder retentionDuration(@Nullable Output<Integer> retentionDuration) {
            $.retentionDuration = retentionDuration;
            return this;
        }

        /**
         * @param retentionDuration (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on until 180).
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder retentionDuration(Integer retentionDuration) {
            return retentionDuration(Output.of(retentionDuration));
        }

        public LogArgs build() {
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("LogArgs", "displayName");
            }
            if ($.logGroupId == null) {
                throw new MissingRequiredPropertyException("LogArgs", "logGroupId");
            }
            if ($.logType == null) {
                throw new MissingRequiredPropertyException("LogArgs", "logType");
            }
            return $;
        }
    }

}
