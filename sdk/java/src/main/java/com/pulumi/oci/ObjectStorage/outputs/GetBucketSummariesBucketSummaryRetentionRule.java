// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ObjectStorage.outputs.GetBucketSummariesBucketSummaryRetentionRuleDuration;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBucketSummariesBucketSummaryRetentionRule {
    private final String displayName;
    private final List<GetBucketSummariesBucketSummaryRetentionRuleDuration> durations;
    private final String retentionRuleId;
    /**
     * @return The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
     * 
     */
    private final String timeCreated;
    private final String timeModified;
    private final String timeRuleLocked;

    @CustomType.Constructor
    private GetBucketSummariesBucketSummaryRetentionRule(
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("durations") List<GetBucketSummariesBucketSummaryRetentionRuleDuration> durations,
        @CustomType.Parameter("retentionRuleId") String retentionRuleId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeModified") String timeModified,
        @CustomType.Parameter("timeRuleLocked") String timeRuleLocked) {
        this.displayName = displayName;
        this.durations = durations;
        this.retentionRuleId = retentionRuleId;
        this.timeCreated = timeCreated;
        this.timeModified = timeModified;
        this.timeRuleLocked = timeRuleLocked;
    }

    public String displayName() {
        return this.displayName;
    }
    public List<GetBucketSummariesBucketSummaryRetentionRuleDuration> durations() {
        return this.durations;
    }
    public String retentionRuleId() {
        return this.retentionRuleId;
    }
    /**
     * @return The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    public String timeModified() {
        return this.timeModified;
    }
    public String timeRuleLocked() {
        return this.timeRuleLocked;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBucketSummariesBucketSummaryRetentionRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String displayName;
        private List<GetBucketSummariesBucketSummaryRetentionRuleDuration> durations;
        private String retentionRuleId;
        private String timeCreated;
        private String timeModified;
        private String timeRuleLocked;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBucketSummariesBucketSummaryRetentionRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.durations = defaults.durations;
    	      this.retentionRuleId = defaults.retentionRuleId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeModified = defaults.timeModified;
    	      this.timeRuleLocked = defaults.timeRuleLocked;
        }

        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder durations(List<GetBucketSummariesBucketSummaryRetentionRuleDuration> durations) {
            this.durations = Objects.requireNonNull(durations);
            return this;
        }
        public Builder durations(GetBucketSummariesBucketSummaryRetentionRuleDuration... durations) {
            return durations(List.of(durations));
        }
        public Builder retentionRuleId(String retentionRuleId) {
            this.retentionRuleId = Objects.requireNonNull(retentionRuleId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeModified(String timeModified) {
            this.timeModified = Objects.requireNonNull(timeModified);
            return this;
        }
        public Builder timeRuleLocked(String timeRuleLocked) {
            this.timeRuleLocked = Objects.requireNonNull(timeRuleLocked);
            return this;
        }        public GetBucketSummariesBucketSummaryRetentionRule build() {
            return new GetBucketSummariesBucketSummaryRetentionRule(displayName, durations, retentionRuleId, timeCreated, timeModified, timeRuleLocked);
        }
    }
}
