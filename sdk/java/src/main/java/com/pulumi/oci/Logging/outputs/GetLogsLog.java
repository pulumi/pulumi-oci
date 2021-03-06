// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Logging.outputs.GetLogsLogConfiguration;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetLogsLog {
    /**
     * @return The OCID of the compartment that the resource belongs to.
     * 
     */
    private final String compartmentId;
    /**
     * @return Log object configuration.
     * 
     */
    private final List<GetLogsLogConfiguration> configurations;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return Resource name
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The OCID of the resource.
     * 
     */
    private final String id;
    /**
     * @return Whether or not this resource is currently enabled.
     * 
     */
    private final Boolean isEnabled;
    /**
     * @return OCID of a log group to work with.
     * 
     */
    private final String logGroupId;
    /**
     * @return The logType that the log object is for, whether custom or service.
     * 
     */
    private final String logType;
    /**
     * @return Log retention duration in 30-day increments (30, 60, 90 and so on).
     * 
     */
    private final Integer retentionDuration;
    /**
     * @return Lifecycle state of the log object
     * 
     */
    private final String state;
    /**
     * @return The OCID of the tenancy.
     * 
     */
    private final String tenancyId;
    /**
     * @return Time the resource was created.
     * 
     */
    private final String timeCreated;
    /**
     * @return Time the resource was last modified.
     * 
     */
    private final String timeLastModified;

    @CustomType.Constructor
    private GetLogsLog(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("configurations") List<GetLogsLogConfiguration> configurations,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isEnabled") Boolean isEnabled,
        @CustomType.Parameter("logGroupId") String logGroupId,
        @CustomType.Parameter("logType") String logType,
        @CustomType.Parameter("retentionDuration") Integer retentionDuration,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("tenancyId") String tenancyId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeLastModified") String timeLastModified) {
        this.compartmentId = compartmentId;
        this.configurations = configurations;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isEnabled = isEnabled;
        this.logGroupId = logGroupId;
        this.logType = logType;
        this.retentionDuration = retentionDuration;
        this.state = state;
        this.tenancyId = tenancyId;
        this.timeCreated = timeCreated;
        this.timeLastModified = timeLastModified;
    }

    /**
     * @return The OCID of the compartment that the resource belongs to.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Log object configuration.
     * 
     */
    public List<GetLogsLogConfiguration> configurations() {
        return this.configurations;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Resource name
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Whether or not this resource is currently enabled.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return OCID of a log group to work with.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }
    /**
     * @return The logType that the log object is for, whether custom or service.
     * 
     */
    public String logType() {
        return this.logType;
    }
    /**
     * @return Log retention duration in 30-day increments (30, 60, 90 and so on).
     * 
     */
    public Integer retentionDuration() {
        return this.retentionDuration;
    }
    /**
     * @return Lifecycle state of the log object
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The OCID of the tenancy.
     * 
     */
    public String tenancyId() {
        return this.tenancyId;
    }
    /**
     * @return Time the resource was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Time the resource was last modified.
     * 
     */
    public String timeLastModified() {
        return this.timeLastModified;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogsLog defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private List<GetLogsLogConfiguration> configurations;
        private Map<String,Object> definedTags;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isEnabled;
        private String logGroupId;
        private String logType;
        private Integer retentionDuration;
        private String state;
        private String tenancyId;
        private String timeCreated;
        private String timeLastModified;

        public Builder() {
    	      // Empty
        }

        public Builder(GetLogsLog defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configurations = defaults.configurations;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.logGroupId = defaults.logGroupId;
    	      this.logType = defaults.logType;
    	      this.retentionDuration = defaults.retentionDuration;
    	      this.state = defaults.state;
    	      this.tenancyId = defaults.tenancyId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastModified = defaults.timeLastModified;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder configurations(List<GetLogsLogConfiguration> configurations) {
            this.configurations = Objects.requireNonNull(configurations);
            return this;
        }
        public Builder configurations(GetLogsLogConfiguration... configurations) {
            return configurations(List.of(configurations));
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        public Builder logGroupId(String logGroupId) {
            this.logGroupId = Objects.requireNonNull(logGroupId);
            return this;
        }
        public Builder logType(String logType) {
            this.logType = Objects.requireNonNull(logType);
            return this;
        }
        public Builder retentionDuration(Integer retentionDuration) {
            this.retentionDuration = Objects.requireNonNull(retentionDuration);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder tenancyId(String tenancyId) {
            this.tenancyId = Objects.requireNonNull(tenancyId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeLastModified(String timeLastModified) {
            this.timeLastModified = Objects.requireNonNull(timeLastModified);
            return this;
        }        public GetLogsLog build() {
            return new GetLogsLog(compartmentId, configurations, definedTags, displayName, freeformTags, id, isEnabled, logGroupId, logType, retentionDuration, state, tenancyId, timeCreated, timeLastModified);
        }
    }
}
