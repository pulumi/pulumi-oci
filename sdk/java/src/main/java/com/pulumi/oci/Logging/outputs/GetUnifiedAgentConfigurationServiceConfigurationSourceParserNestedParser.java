// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetUnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser {
    /**
     * @return Specify the time field for the event time. If the event doesn&#39;t have this field, the current time is used.
     * 
     */
    private String fieldTimeKey;
    /**
     * @return If true, keep time field in the record.
     * 
     */
    private Boolean isKeepTimeKey;
    /**
     * @return Process time value using the specified format.
     * 
     */
    private String timeFormat;
    /**
     * @return Time type of JSON parser.
     * 
     */
    private String timeType;

    private GetUnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser() {}
    /**
     * @return Specify the time field for the event time. If the event doesn&#39;t have this field, the current time is used.
     * 
     */
    public String fieldTimeKey() {
        return this.fieldTimeKey;
    }
    /**
     * @return If true, keep time field in the record.
     * 
     */
    public Boolean isKeepTimeKey() {
        return this.isKeepTimeKey;
    }
    /**
     * @return Process time value using the specified format.
     * 
     */
    public String timeFormat() {
        return this.timeFormat;
    }
    /**
     * @return Time type of JSON parser.
     * 
     */
    public String timeType() {
        return this.timeType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String fieldTimeKey;
        private Boolean isKeepTimeKey;
        private String timeFormat;
        private String timeType;
        public Builder() {}
        public Builder(GetUnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.fieldTimeKey = defaults.fieldTimeKey;
    	      this.isKeepTimeKey = defaults.isKeepTimeKey;
    	      this.timeFormat = defaults.timeFormat;
    	      this.timeType = defaults.timeType;
        }

        @CustomType.Setter
        public Builder fieldTimeKey(String fieldTimeKey) {
            this.fieldTimeKey = Objects.requireNonNull(fieldTimeKey);
            return this;
        }
        @CustomType.Setter
        public Builder isKeepTimeKey(Boolean isKeepTimeKey) {
            this.isKeepTimeKey = Objects.requireNonNull(isKeepTimeKey);
            return this;
        }
        @CustomType.Setter
        public Builder timeFormat(String timeFormat) {
            this.timeFormat = Objects.requireNonNull(timeFormat);
            return this;
        }
        @CustomType.Setter
        public Builder timeType(String timeType) {
            this.timeType = Objects.requireNonNull(timeType);
            return this;
        }
        public GetUnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser build() {
            final var o = new GetUnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser();
            o.fieldTimeKey = fieldTimeKey;
            o.isKeepTimeKey = isKeepTimeKey;
            o.timeFormat = timeFormat;
            o.timeType = timeType;
            return o;
        }
    }
}