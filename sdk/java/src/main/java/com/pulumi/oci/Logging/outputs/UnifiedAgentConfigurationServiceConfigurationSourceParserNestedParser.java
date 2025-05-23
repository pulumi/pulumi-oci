// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser {
    /**
     * @return Specify the time field for the event time. If the event doesn&#39;t have this field, the current time is used.
     * 
     */
    private @Nullable String fieldTimeKey;
    /**
     * @return If true, keep the time field in the record.
     * 
     */
    private @Nullable Boolean isKeepTimeKey;
    /**
     * @return (Updatable) If true, a separator parameter can be further defined.
     * 
     */
    private @Nullable Boolean parseNested;
    /**
     * @return (Updatable) Keys of adjacent levels are joined by the separator.
     * 
     */
    private @Nullable String separator;
    /**
     * @return (Updatable) Process time value using the specified format.
     * 
     */
    private @Nullable String timeFormat;
    /**
     * @return (Updatable) JSON parser time type.
     * 
     */
    private @Nullable String timeType;

    private UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser() {}
    /**
     * @return Specify the time field for the event time. If the event doesn&#39;t have this field, the current time is used.
     * 
     */
    public Optional<String> fieldTimeKey() {
        return Optional.ofNullable(this.fieldTimeKey);
    }
    /**
     * @return If true, keep the time field in the record.
     * 
     */
    public Optional<Boolean> isKeepTimeKey() {
        return Optional.ofNullable(this.isKeepTimeKey);
    }
    /**
     * @return (Updatable) If true, a separator parameter can be further defined.
     * 
     */
    public Optional<Boolean> parseNested() {
        return Optional.ofNullable(this.parseNested);
    }
    /**
     * @return (Updatable) Keys of adjacent levels are joined by the separator.
     * 
     */
    public Optional<String> separator() {
        return Optional.ofNullable(this.separator);
    }
    /**
     * @return (Updatable) Process time value using the specified format.
     * 
     */
    public Optional<String> timeFormat() {
        return Optional.ofNullable(this.timeFormat);
    }
    /**
     * @return (Updatable) JSON parser time type.
     * 
     */
    public Optional<String> timeType() {
        return Optional.ofNullable(this.timeType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String fieldTimeKey;
        private @Nullable Boolean isKeepTimeKey;
        private @Nullable Boolean parseNested;
        private @Nullable String separator;
        private @Nullable String timeFormat;
        private @Nullable String timeType;
        public Builder() {}
        public Builder(UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.fieldTimeKey = defaults.fieldTimeKey;
    	      this.isKeepTimeKey = defaults.isKeepTimeKey;
    	      this.parseNested = defaults.parseNested;
    	      this.separator = defaults.separator;
    	      this.timeFormat = defaults.timeFormat;
    	      this.timeType = defaults.timeType;
        }

        @CustomType.Setter
        public Builder fieldTimeKey(@Nullable String fieldTimeKey) {

            this.fieldTimeKey = fieldTimeKey;
            return this;
        }
        @CustomType.Setter
        public Builder isKeepTimeKey(@Nullable Boolean isKeepTimeKey) {

            this.isKeepTimeKey = isKeepTimeKey;
            return this;
        }
        @CustomType.Setter
        public Builder parseNested(@Nullable Boolean parseNested) {

            this.parseNested = parseNested;
            return this;
        }
        @CustomType.Setter
        public Builder separator(@Nullable String separator) {

            this.separator = separator;
            return this;
        }
        @CustomType.Setter
        public Builder timeFormat(@Nullable String timeFormat) {

            this.timeFormat = timeFormat;
            return this;
        }
        @CustomType.Setter
        public Builder timeType(@Nullable String timeType) {

            this.timeType = timeType;
            return this;
        }
        public UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser build() {
            final var _resultValue = new UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParser();
            _resultValue.fieldTimeKey = fieldTimeKey;
            _resultValue.isKeepTimeKey = isKeepTimeKey;
            _resultValue.parseNested = parseNested;
            _resultValue.separator = separator;
            _resultValue.timeFormat = timeFormat;
            _resultValue.timeType = timeType;
            return _resultValue;
        }
    }
}
