// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetLogAnalyticsObjectCollectionRuleOverride {
    private final String matchType;
    private final String matchValue;
    private final String propertyName;
    private final String propertyValue;

    @CustomType.Constructor
    private GetLogAnalyticsObjectCollectionRuleOverride(
        @CustomType.Parameter("matchType") String matchType,
        @CustomType.Parameter("matchValue") String matchValue,
        @CustomType.Parameter("propertyName") String propertyName,
        @CustomType.Parameter("propertyValue") String propertyValue) {
        this.matchType = matchType;
        this.matchValue = matchValue;
        this.propertyName = propertyName;
        this.propertyValue = propertyValue;
    }

    public String matchType() {
        return this.matchType;
    }
    public String matchValue() {
        return this.matchValue;
    }
    public String propertyName() {
        return this.propertyName;
    }
    public String propertyValue() {
        return this.propertyValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogAnalyticsObjectCollectionRuleOverride defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String matchType;
        private String matchValue;
        private String propertyName;
        private String propertyValue;

        public Builder() {
    	      // Empty
        }

        public Builder(GetLogAnalyticsObjectCollectionRuleOverride defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.matchType = defaults.matchType;
    	      this.matchValue = defaults.matchValue;
    	      this.propertyName = defaults.propertyName;
    	      this.propertyValue = defaults.propertyValue;
        }

        public Builder matchType(String matchType) {
            this.matchType = Objects.requireNonNull(matchType);
            return this;
        }
        public Builder matchValue(String matchValue) {
            this.matchValue = Objects.requireNonNull(matchValue);
            return this;
        }
        public Builder propertyName(String propertyName) {
            this.propertyName = Objects.requireNonNull(propertyName);
            return this;
        }
        public Builder propertyValue(String propertyValue) {
            this.propertyValue = Objects.requireNonNull(propertyValue);
            return this;
        }        public GetLogAnalyticsObjectCollectionRuleOverride build() {
            return new GetLogAnalyticsObjectCollectionRuleOverride(matchType, matchValue, propertyName, propertyValue);
        }
    }
}
