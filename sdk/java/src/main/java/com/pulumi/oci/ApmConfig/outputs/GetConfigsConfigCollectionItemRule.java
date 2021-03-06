// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmConfig.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetConfigsConfigCollectionItemRule {
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private final String displayName;
    /**
     * @return The string that defines the Span Filter expression.
     * 
     */
    private final String filterText;
    /**
     * @return If true, the rule will compute the actual Apdex score for spans that have been marked as errors. If false, the rule will always set the Apdex for error spans to frustrating, regardless of the configured thresholds. Default is false.
     * 
     */
    private final Boolean isApplyToErrorSpans;
    /**
     * @return Specifies if the Apdex rule will be computed for spans matching the rule. Can be used to make sure certain spans don&#39;t get an Apdex score. The default is &#34;true&#34;.
     * 
     */
    private final Boolean isEnabled;
    /**
     * @return The priority controls the order in which multiple rules in a rule set are applied. Lower values indicate higher priorities. Rules with higher priority are applied first, and once a match is found, the rest of the rules are ignored. Rules within the same rule set cannot have the same priority.
     * 
     */
    private final Integer priority;
    /**
     * @return The maximum response time in milliseconds that will be considered satisfactory for the end user.
     * 
     */
    private final Integer satisfiedResponseTime;
    /**
     * @return The maximum response time in milliseconds that will be considered tolerable for the end user. Response times beyond this threshold will be considered frustrating. This value cannot be lower than &#34;satisfiedResponseTime&#34;.
     * 
     */
    private final Integer toleratingResponseTime;

    @CustomType.Constructor
    private GetConfigsConfigCollectionItemRule(
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("filterText") String filterText,
        @CustomType.Parameter("isApplyToErrorSpans") Boolean isApplyToErrorSpans,
        @CustomType.Parameter("isEnabled") Boolean isEnabled,
        @CustomType.Parameter("priority") Integer priority,
        @CustomType.Parameter("satisfiedResponseTime") Integer satisfiedResponseTime,
        @CustomType.Parameter("toleratingResponseTime") Integer toleratingResponseTime) {
        this.displayName = displayName;
        this.filterText = filterText;
        this.isApplyToErrorSpans = isApplyToErrorSpans;
        this.isEnabled = isEnabled;
        this.priority = priority;
        this.satisfiedResponseTime = satisfiedResponseTime;
        this.toleratingResponseTime = toleratingResponseTime;
    }

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The string that defines the Span Filter expression.
     * 
     */
    public String filterText() {
        return this.filterText;
    }
    /**
     * @return If true, the rule will compute the actual Apdex score for spans that have been marked as errors. If false, the rule will always set the Apdex for error spans to frustrating, regardless of the configured thresholds. Default is false.
     * 
     */
    public Boolean isApplyToErrorSpans() {
        return this.isApplyToErrorSpans;
    }
    /**
     * @return Specifies if the Apdex rule will be computed for spans matching the rule. Can be used to make sure certain spans don&#39;t get an Apdex score. The default is &#34;true&#34;.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return The priority controls the order in which multiple rules in a rule set are applied. Lower values indicate higher priorities. Rules with higher priority are applied first, and once a match is found, the rest of the rules are ignored. Rules within the same rule set cannot have the same priority.
     * 
     */
    public Integer priority() {
        return this.priority;
    }
    /**
     * @return The maximum response time in milliseconds that will be considered satisfactory for the end user.
     * 
     */
    public Integer satisfiedResponseTime() {
        return this.satisfiedResponseTime;
    }
    /**
     * @return The maximum response time in milliseconds that will be considered tolerable for the end user. Response times beyond this threshold will be considered frustrating. This value cannot be lower than &#34;satisfiedResponseTime&#34;.
     * 
     */
    public Integer toleratingResponseTime() {
        return this.toleratingResponseTime;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConfigsConfigCollectionItemRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String displayName;
        private String filterText;
        private Boolean isApplyToErrorSpans;
        private Boolean isEnabled;
        private Integer priority;
        private Integer satisfiedResponseTime;
        private Integer toleratingResponseTime;

        public Builder() {
    	      // Empty
        }

        public Builder(GetConfigsConfigCollectionItemRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.filterText = defaults.filterText;
    	      this.isApplyToErrorSpans = defaults.isApplyToErrorSpans;
    	      this.isEnabled = defaults.isEnabled;
    	      this.priority = defaults.priority;
    	      this.satisfiedResponseTime = defaults.satisfiedResponseTime;
    	      this.toleratingResponseTime = defaults.toleratingResponseTime;
        }

        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder filterText(String filterText) {
            this.filterText = Objects.requireNonNull(filterText);
            return this;
        }
        public Builder isApplyToErrorSpans(Boolean isApplyToErrorSpans) {
            this.isApplyToErrorSpans = Objects.requireNonNull(isApplyToErrorSpans);
            return this;
        }
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        public Builder priority(Integer priority) {
            this.priority = Objects.requireNonNull(priority);
            return this;
        }
        public Builder satisfiedResponseTime(Integer satisfiedResponseTime) {
            this.satisfiedResponseTime = Objects.requireNonNull(satisfiedResponseTime);
            return this;
        }
        public Builder toleratingResponseTime(Integer toleratingResponseTime) {
            this.toleratingResponseTime = Objects.requireNonNull(toleratingResponseTime);
            return this;
        }        public GetConfigsConfigCollectionItemRule build() {
            return new GetConfigsConfigCollectionItemRule(displayName, filterText, isApplyToErrorSpans, isEnabled, priority, satisfiedResponseTime, toleratingResponseTime);
        }
    }
}
